//! Bounded, capability-confined directory scope documents.
//!
//! A policy scope document (`.bifrost/policy-scope.json` by convention) lists
//! workspace-relative directories whose findings are pre-accepted for some or
//! all policies. Scoped findings stay in the canonical report with an attached
//! decision but no longer count toward the failure status. Scope complements
//! per-finding suppression: a suppression accepts one finding of one rule
//! version, a scope entry is a standing statement about a directory (a fixture
//! corpus, a test tree).

use std::cmp::Ordering;
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
use super::definition::{PolicyCategoryId, PolicyId, PolicyIdentifierError};
use super::retained::{RetainedSize, retained_extra};

pub const DEFAULT_POLICY_SCOPE_PATH: &str = ".bifrost/policy-scope.json";
pub const MAX_POLICY_SCOPE_DOCUMENT_BYTES: u64 = 256 * 1024;
pub const MAX_POLICY_SCOPES: usize = 256;
pub const MAX_POLICY_SCOPE_REASON_BYTES: usize = 4_096;
pub const MAX_POLICY_SCOPE_PATH_BYTES: usize = 1_024;
pub const MAX_POLICY_SCOPE_SELECTORS: usize = 64;

const POLICY_SCOPE_SCHEMA_VERSION: u32 = 1;
const MAX_JSON_ERROR_BYTES: usize = 512;

/// One normalized directory scope entry.
///
/// Empty selector slices mean the entry applies to every policy; a non-empty
/// entry applies to a policy when its id is listed or any of its categories is
/// listed (union semantics).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyScopeEntry {
    #[serde(serialize_with = "serialize_workspace_relative_path")]
    path: WorkspaceRelativePath,
    reason: Box<str>,
    policy_ids: Box<[PolicyId]>,
    policy_categories: Box<[PolicyCategoryId]>,
}

impl PolicyScopeEntry {
    pub fn path(&self) -> &str {
        self.path.as_str()
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }

    pub fn policy_ids(&self) -> &[PolicyId] {
        &self.policy_ids
    }

    pub fn policy_categories(&self) -> &[PolicyCategoryId] {
        &self.policy_categories
    }

    /// Whether this entry accepts findings of `policy_id` (with `categories`
    /// from the policy's metadata) anchored at `primary_path`.
    pub fn matches(
        &self,
        primary_path: &str,
        policy_id: &PolicyId,
        categories: &[PolicyCategoryId],
    ) -> bool {
        self.matches_policy(policy_id, categories) && self.contains_path(primary_path)
    }

    fn matches_policy(&self, policy_id: &PolicyId, categories: &[PolicyCategoryId]) -> bool {
        if self.policy_ids.is_empty() && self.policy_categories.is_empty() {
            return true;
        }
        self.policy_ids.contains(policy_id)
            || categories
                .iter()
                .any(|category| self.policy_categories.contains(category))
    }

    /// The decision metadata attached to a finding this entry accepts.
    pub(crate) fn finding_scope(&self) -> PolicyFindingScope {
        PolicyFindingScope {
            path: self.path.as_str().into(),
            reason: self.reason.clone(),
        }
    }

    /// Component-wise directory-prefix test on a portable slash-separated
    /// workspace-relative path, so `tests` matches `tests/a.rs` but not
    /// `tests_extra/a.rs`.
    fn contains_path(&self, primary_path: &str) -> bool {
        let prefix = self.path.as_str();
        primary_path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
    }
}

/// Canonically sorted schema-version-one scope document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyScopeDocument {
    schema_version: u32,
    scopes: Box<[PolicyScopeEntry]>,
}

impl PolicyScopeDocument {
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub fn scopes(&self) -> &[PolicyScopeEntry] {
        &self.scopes
    }
}

/// Location used to load one scope document.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum PolicyScopeSource {
    #[default]
    Conventional,
    Explicit(WorkspaceRelativePath),
}

impl PolicyScopeSource {
    pub fn explicit(path: impl AsRef<Path>) -> Result<Self, PolicyScopeSourceError> {
        Self::from_workspace_path(WorkspaceRelativePath::try_from_path(path.as_ref())?)
    }

    pub fn explicit_portable(path: impl AsRef<str>) -> Result<Self, PolicyScopeSourceError> {
        Self::from_workspace_path(WorkspaceRelativePath::new(path)?)
    }

    pub fn relative_path(&self) -> &str {
        match self {
            Self::Conventional => DEFAULT_POLICY_SCOPE_PATH,
            Self::Explicit(path) => path.as_str(),
        }
    }

    fn from_workspace_path(path: WorkspaceRelativePath) -> Result<Self, PolicyScopeSourceError> {
        if path.as_str().len() > MAX_POLICY_SCOPE_PATH_BYTES {
            return Err(PolicyScopeSourceError::TooLong {
                max_bytes: MAX_POLICY_SCOPE_PATH_BYTES,
            });
        }
        Ok(Self::Explicit(path))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PolicyScopeOptions {
    source: PolicyScopeSource,
}

impl PolicyScopeOptions {
    pub const fn new(source: PolicyScopeSource) -> Self {
        Self { source }
    }

    pub const fn source(&self) -> &PolicyScopeSource {
        &self.source
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyScopeSourceError {
    Path(WorkspaceRelativePathError),
    TooLong { max_bytes: usize },
}

impl From<WorkspaceRelativePathError> for PolicyScopeSourceError {
    fn from(error: WorkspaceRelativePathError) -> Self {
        Self::Path(error)
    }
}

impl fmt::Display for PolicyScopeSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path(error) => error.fmt(formatter),
            Self::TooLong { max_bytes } => {
                write!(formatter, "scope path must be at most {max_bytes} bytes")
            }
        }
    }
}

impl std::error::Error for PolicyScopeSourceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Path(error) => Some(error),
            Self::TooLong { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyScopeDocumentState {
    NotEvaluated,
    NotFound,
    Loaded,
    Invalid,
}

/// Active scope metadata attached to a retained finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyFindingScope {
    path: Box<str>,
    reason: Box<str>,
}

impl PolicyFindingScope {
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// Canonical audit disposition for one loaded scope entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyScopeReview {
    #[serde(flatten)]
    entry: PolicyScopeEntry,
    matched_findings: u64,
    applied: bool,
    result_omitted: bool,
}

impl PolicyScopeReview {
    pub(crate) fn new(entry: &PolicyScopeEntry, matched_findings: u64) -> Self {
        Self {
            entry: entry.clone(),
            matched_findings,
            applied: matched_findings > 0,
            result_omitted: false,
        }
    }

    pub const fn entry(&self) -> &PolicyScopeEntry {
        &self.entry
    }

    pub const fn matched_findings(&self) -> u64 {
        self.matched_findings
    }

    pub const fn applied(&self) -> bool {
        self.applied
    }

    pub const fn result_omitted(&self) -> bool {
        self.result_omitted
    }

    pub(crate) fn mark_result_omitted(&mut self) {
        self.result_omitted = true;
    }

    /// Whether a finding-attached scope decision was produced by this entry.
    pub(crate) fn covers(&self, finding_scope: &PolicyFindingScope) -> bool {
        self.entry.path.as_str() == finding_scope.path()
            && self.entry.reason() == finding_scope.reason()
    }
}

pub(crate) fn compare_scope_reviews(
    left: &PolicyScopeReview,
    right: &PolicyScopeReview,
) -> Ordering {
    compare_scope_key(&left.entry, &right.entry)
}

/// Open a workspace capability once, then load and normalize its configured
/// scope document. Only an actual missing file maps to `Ok(None)`.
pub fn load_policy_scope(
    workspace_root: &Path,
    options: &PolicyScopeOptions,
) -> Result<Option<PolicyScopeDocument>, PolicyScopeLoadError> {
    let root = WorkspaceRoot::open(workspace_root).map_err(PolicyScopeLoadError::Workspace)?;
    load_policy_scope_from_root(&root, options)
}

pub(crate) fn load_policy_scope_from_root(
    root: &WorkspaceRoot,
    options: &PolicyScopeOptions,
) -> Result<Option<PolicyScopeDocument>, PolicyScopeLoadError> {
    let relative_path = Path::new(options.source.relative_path());
    let document = match read_workspace_document(
        root,
        relative_path,
        &["json"],
        MAX_POLICY_SCOPE_DOCUMENT_BYTES,
    ) {
        Ok(document) => document,
        Err(error) if workspace_error_is_not_found(&error) => return Ok(None),
        Err(error) => return Err(PolicyScopeLoadError::Workspace(error)),
    };
    parse_policy_scope_document(document.source())
        .map(Some)
        .map_err(PolicyScopeLoadError::Document)
}

pub fn parse_policy_scope_document(
    source: &str,
) -> Result<PolicyScopeDocument, PolicyScopeDocumentError> {
    if u64::try_from(source.len()).unwrap_or(u64::MAX) > MAX_POLICY_SCOPE_DOCUMENT_BYTES {
        return Err(PolicyScopeDocumentError::Validation(
            PolicyScopeValidationError::DocumentTooLarge {
                max_bytes: MAX_POLICY_SCOPE_DOCUMENT_BYTES,
            },
        ));
    }
    let wire = serde_json::from_str::<WireScopeDocument>(source).map_err(|error| {
        PolicyScopeDocumentError::JsonDecode {
            message: bounded_error_message(&error.to_string()),
            line: error.line(),
            column: error.column(),
        }
    })?;
    normalize_wire_document(wire).map_err(PolicyScopeDocumentError::Validation)
}

fn normalize_wire_document(
    wire: WireScopeDocument,
) -> Result<PolicyScopeDocument, PolicyScopeValidationError> {
    if wire.schema_version != u64::from(POLICY_SCOPE_SCHEMA_VERSION) {
        return Err(PolicyScopeValidationError::UnsupportedSchemaVersion {
            observed: wire.schema_version,
        });
    }
    if wire.scopes.len() > MAX_POLICY_SCOPES {
        return Err(PolicyScopeValidationError::TooManyScopes {
            max: MAX_POLICY_SCOPES,
        });
    }
    let mut scopes = Vec::with_capacity(wire.scopes.len());
    for (index, entry) in wire.scopes.into_iter().enumerate() {
        scopes.push(normalize_wire_entry(index, entry)?);
    }
    scopes.sort_by(compare_scope_key);
    for entries in scopes.windows(2) {
        if compare_scope_key(&entries[0], &entries[1]) == Ordering::Equal {
            return Err(PolicyScopeValidationError::DuplicateScope {
                path: entries[1].path.as_str().into(),
            });
        }
    }
    scopes.shrink_to_fit();
    Ok(PolicyScopeDocument {
        schema_version: POLICY_SCOPE_SCHEMA_VERSION,
        scopes: scopes.into_boxed_slice(),
    })
}

fn normalize_wire_entry(
    index: usize,
    wire: WireScopeEntry,
) -> Result<PolicyScopeEntry, PolicyScopeValidationError> {
    if wire.path.len() > MAX_POLICY_SCOPE_PATH_BYTES {
        return Err(PolicyScopeValidationError::PathTooLong {
            index,
            max_bytes: MAX_POLICY_SCOPE_PATH_BYTES,
        });
    }
    let path = WorkspaceRelativePath::new(&wire.path)
        .map_err(|source| PolicyScopeValidationError::InvalidPath { index, source })?;
    validate_required_text(&wire.reason, MAX_POLICY_SCOPE_REASON_BYTES)
        .map_err(|source| PolicyScopeValidationError::InvalidReason { index, source })?;
    if wire.reason.trim().is_empty() {
        return Err(PolicyScopeValidationError::BlankReason { index });
    }
    let policy_ids = normalize_selector(index, wire.policy_ids, "policy_ids", |value| {
        PolicyId::new(value)
            .map_err(|source| PolicyScopeValidationError::InvalidPolicyId { index, source })
    })?;
    let policy_categories = normalize_selector(
        index,
        wire.policy_categories,
        "policy_categories",
        |value| {
            PolicyCategoryId::new(value).map_err(|source| {
                PolicyScopeValidationError::InvalidPolicyCategory { index, source }
            })
        },
    )?;
    Ok(PolicyScopeEntry {
        path,
        reason: wire.reason.into_boxed_str(),
        policy_ids,
        policy_categories,
    })
}

fn normalize_selector<T: Ord>(
    index: usize,
    values: Option<Vec<String>>,
    field: &'static str,
    parse: impl Fn(&str) -> Result<T, PolicyScopeValidationError>,
) -> Result<Box<[T]>, PolicyScopeValidationError> {
    let Some(values) = values else {
        return Ok(Box::default());
    };
    if values.is_empty() {
        return Err(PolicyScopeValidationError::EmptySelector { index, field });
    }
    if values.len() > MAX_POLICY_SCOPE_SELECTORS {
        return Err(PolicyScopeValidationError::TooManySelectors {
            index,
            field,
            max: MAX_POLICY_SCOPE_SELECTORS,
        });
    }
    let mut parsed = values
        .iter()
        .map(|value| parse(value))
        .collect::<Result<Vec<_>, _>>()?;
    parsed.sort();
    if parsed.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(PolicyScopeValidationError::DuplicateSelector { index, field });
    }
    Ok(parsed.into_boxed_slice())
}

fn serialize_workspace_relative_path<S>(
    path: &WorkspaceRelativePath,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(path.as_str())
}

fn compare_scope_key(left: &PolicyScopeEntry, right: &PolicyScopeEntry) -> Ordering {
    left.path
        .cmp(&right.path)
        .then_with(|| left.policy_ids.cmp(&right.policy_ids))
        .then_with(|| left.policy_categories.cmp(&right.policy_categories))
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireScopeDocument {
    schema_version: u64,
    scopes: Vec<WireScopeEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireScopeEntry {
    path: String,
    reason: String,
    #[serde(default)]
    policy_ids: Option<Vec<String>>,
    #[serde(default)]
    policy_categories: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyScopeDocumentError {
    JsonDecode {
        message: Box<str>,
        line: usize,
        column: usize,
    },
    Validation(PolicyScopeValidationError),
}

impl fmt::Display for PolicyScopeDocumentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::JsonDecode {
                message,
                line,
                column,
            } => write!(
                formatter,
                "scope document is not valid JSON at line {line} column {column}: {message}"
            ),
            Self::Validation(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for PolicyScopeDocumentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::JsonDecode { .. } => None,
            Self::Validation(error) => Some(error),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyScopeValidationError {
    DocumentTooLarge {
        max_bytes: u64,
    },
    UnsupportedSchemaVersion {
        observed: u64,
    },
    TooManyScopes {
        max: usize,
    },
    PathTooLong {
        index: usize,
        max_bytes: usize,
    },
    InvalidPath {
        index: usize,
        source: WorkspaceRelativePathError,
    },
    InvalidReason {
        index: usize,
        source: TextValidationError,
    },
    BlankReason {
        index: usize,
    },
    EmptySelector {
        index: usize,
        field: &'static str,
    },
    TooManySelectors {
        index: usize,
        field: &'static str,
        max: usize,
    },
    DuplicateSelector {
        index: usize,
        field: &'static str,
    },
    InvalidPolicyId {
        index: usize,
        source: PolicyIdentifierError,
    },
    InvalidPolicyCategory {
        index: usize,
        source: PolicyIdentifierError,
    },
    DuplicateScope {
        path: Box<str>,
    },
}

impl fmt::Display for PolicyScopeValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DocumentTooLarge { max_bytes } => {
                write!(
                    formatter,
                    "scope document must be at most {max_bytes} bytes"
                )
            }
            Self::UnsupportedSchemaVersion { observed } => write!(
                formatter,
                "scope document schema_version {observed} is unsupported; expected {POLICY_SCOPE_SCHEMA_VERSION}"
            ),
            Self::TooManyScopes { max } => {
                write!(formatter, "scope document must list at most {max} scopes")
            }
            Self::PathTooLong { index, max_bytes } => write!(
                formatter,
                "scope {index} path must be at most {max_bytes} bytes"
            ),
            Self::InvalidPath { index, source } => {
                write!(formatter, "scope {index} path is invalid: {source}")
            }
            Self::InvalidReason { index, source } => {
                write!(formatter, "scope {index} reason is invalid: {source}")
            }
            Self::BlankReason { index } => {
                write!(formatter, "scope {index} reason must not be blank")
            }
            Self::EmptySelector { index, field } => write!(
                formatter,
                "scope {index} {field} must not be an empty array; omit the field to select every policy"
            ),
            Self::TooManySelectors { index, field, max } => {
                write!(
                    formatter,
                    "scope {index} {field} must list at most {max} values"
                )
            }
            Self::DuplicateSelector { index, field } => {
                write!(
                    formatter,
                    "scope {index} {field} contains a duplicate value"
                )
            }
            Self::InvalidPolicyId { index, source } => {
                write!(formatter, "scope {index} policy id is invalid: {source}")
            }
            Self::InvalidPolicyCategory { index, source } => {
                write!(
                    formatter,
                    "scope {index} policy category is invalid: {source}"
                )
            }
            Self::DuplicateScope { path } => write!(
                formatter,
                "scope document lists duplicate scopes for path {path}"
            ),
        }
    }
}

impl std::error::Error for PolicyScopeValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidPath { source, .. } => Some(source),
            Self::InvalidReason { source, .. } => Some(source),
            Self::InvalidPolicyId { source, .. } | Self::InvalidPolicyCategory { source, .. } => {
                Some(source)
            }
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum PolicyScopeLoadError {
    Workspace(WorkspaceDocumentError),
    Document(PolicyScopeDocumentError),
}

impl fmt::Display for PolicyScopeLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Workspace(error) => error.fmt(formatter),
            Self::Document(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for PolicyScopeLoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Workspace(error) => Some(error),
            Self::Document(error) => Some(error),
        }
    }
}

impl RetainedSize for PolicyScopeEntry {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(self.path.as_str().len())
            .saturating_add(retained_extra(&self.reason))
            .saturating_add(
                self.policy_ids
                    .iter()
                    .fold(0usize, |bytes, id| bytes.saturating_add(retained_extra(id))),
            )
            .saturating_add(
                self.policy_categories
                    .iter()
                    .fold(0usize, |bytes, id| bytes.saturating_add(retained_extra(id))),
            )
    }
}

impl RetainedSize for PolicyScopeDocument {
    fn retained_size(&self) -> usize {
        self.scopes
            .iter()
            .fold(std::mem::size_of::<Self>(), |bytes, scope| {
                bytes.saturating_add(scope.retained_size())
            })
    }
}

impl RetainedSize for PolicyScopeSource {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>().saturating_add(match self {
            Self::Conventional => 0,
            Self::Explicit(path) => path.as_str().len(),
        })
    }
}

impl RetainedSize for PolicyScopeOptions {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>().saturating_add(self.source.retained_size())
    }
}

impl RetainedSize for PolicyFindingScope {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(retained_extra(&self.path))
            .saturating_add(retained_extra(&self.reason))
    }
}

impl RetainedSize for PolicyScopeReview {
    fn retained_size(&self) -> usize {
        std::mem::size_of::<Self>().saturating_add(self.entry.retained_size())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(source: &str) -> Result<PolicyScopeDocument, PolicyScopeDocumentError> {
        parse_policy_scope_document(source)
    }

    fn entry(document: &PolicyScopeDocument, index: usize) -> &PolicyScopeEntry {
        &document.scopes()[index]
    }

    #[test]
    fn parses_and_sorts_a_valid_document() {
        let document = parse(
            r#"{
                "schema_version": 1,
                "scopes": [
                    {
                        "path": "tests",
                        "reason": "Test code is not performance-sensitive.",
                        "policy_categories": ["performance"]
                    },
                    {
                        "path": "tests/fixtures",
                        "reason": "Intentional smell corpus."
                    }
                ]
            }"#,
        )
        .unwrap();
        assert_eq!(document.schema_version(), 1);
        assert_eq!(document.scopes().len(), 2);
        assert_eq!(entry(&document, 0).path(), "tests");
        assert_eq!(entry(&document, 1).path(), "tests/fixtures");
        assert!(entry(&document, 1).policy_ids().is_empty());
        assert!(entry(&document, 1).policy_categories().is_empty());
    }

    #[test]
    fn component_wise_prefix_matching() {
        let document = parse(
            r#"{
                "schema_version": 1,
                "scopes": [
                    {"path": "tests", "reason": "Test tree."}
                ]
            }"#,
        )
        .unwrap();
        let scope = entry(&document, 0);
        let policy = PolicyId::new("bifrost.performance.sleep-in-loop").unwrap();
        assert!(scope.matches("tests/a.rs", &policy, &[]));
        assert!(scope.matches("tests", &policy, &[]));
        assert!(!scope.matches("tests_extra/a.rs", &policy, &[]));
        assert!(!scope.matches("src/tests/a.rs", &policy, &[]));
    }

    #[test]
    fn selector_union_semantics() {
        let document = parse(
            r#"{
                "schema_version": 1,
                "scopes": [
                    {
                        "path": "tests",
                        "reason": "Performance prompts and one exact rule.",
                        "policy_ids": ["bifrost.correctness.dynamic-evaluation"],
                        "policy_categories": ["performance"]
                    }
                ]
            }"#,
        )
        .unwrap();
        let scope = entry(&document, 0);
        let performance = PolicyCategoryId::new("performance").unwrap();
        let correctness = PolicyCategoryId::new("correctness").unwrap();
        let sleep = PolicyId::new("bifrost.performance.sleep-in-loop").unwrap();
        let dynamic = PolicyId::new("bifrost.correctness.dynamic-evaluation").unwrap();
        let unsafe_deser = PolicyId::new("bifrost.correctness.unsafe-deserialization").unwrap();
        assert!(scope.matches("tests/a.py", &sleep, std::slice::from_ref(&performance)));
        assert!(scope.matches("tests/a.py", &dynamic, std::slice::from_ref(&correctness)));
        assert!(!scope.matches(
            "tests/a.py",
            &unsafe_deser,
            std::slice::from_ref(&correctness)
        ));
    }

    #[test]
    fn rejects_invalid_documents() {
        let cases = [
            (r#"{"schema_version": 2, "scopes": []}"#, "schema_version"),
            (
                r#"{"schema_version": 1, "scopes": [{"path": "/abs", "reason": "x"}]}"#,
                "path",
            ),
            (
                r#"{"schema_version": 1, "scopes": [{"path": "a/../b", "reason": "x"}]}"#,
                "path",
            ),
            (
                r#"{"schema_version": 1, "scopes": [{"path": "tests", "reason": "   "}]}"#,
                "reason",
            ),
            (
                r#"{"schema_version": 1, "scopes": [{"path": "tests", "reason": "x", "policy_ids": []}]}"#,
                "policy_ids",
            ),
            (
                r#"{"schema_version": 1, "scopes": [{"path": "tests", "reason": "x", "policy_categories": ["performance", "performance"]}]}"#,
                "duplicate",
            ),
            (
                r#"{"schema_version": 1, "scopes": [{"path": "tests", "reason": "a"}, {"path": "tests", "reason": "b"}]}"#,
                "duplicate",
            ),
            (
                r#"{"schema_version": 1, "scopes": [{"path": "tests", "reason": "x", "unknown": 1}]}"#,
                "unknown",
            ),
        ];
        for (source, needle) in cases {
            let error = parse(source).unwrap_err();
            let message = error.to_string();
            assert!(
                message.contains(needle),
                "expected error for {source} to mention {needle}, got: {message}"
            );
        }
    }

    #[test]
    fn same_path_with_different_selectors_is_allowed() {
        let document = parse(
            r#"{
                "schema_version": 1,
                "scopes": [
                    {"path": "tests", "reason": "a", "policy_categories": ["performance"]},
                    {"path": "tests", "reason": "b", "policy_categories": ["correctness"]}
                ]
            }"#,
        )
        .unwrap();
        assert_eq!(document.scopes().len(), 2);
    }
}
