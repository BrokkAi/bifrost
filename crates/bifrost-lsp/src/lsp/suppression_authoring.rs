//! Protocol models for authoring a policy suppression from an editor finding.
//!
//! The LSP owns the request envelope and destination policy.  Parsing and
//! canonical serialization of the suppression document remain in
//! `brokk-bifrost-policy`.

use lsp_types::Uri;
use serde::{Deserialize, Serialize};

use crate::policy::PolicyEvaluationDate;

/// The three conventional destinations exposed by the editor.  Keeping this
/// closed prevents an editor request from turning this operation into an
/// arbitrary workspace file writer.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum PolicySuppressionDestination {
    Public,
    Private,
    Local,
}

impl PolicySuppressionDestination {
    pub(crate) const fn relative_path(self) -> &'static str {
        match self {
            Self::Public => ".bifrost/suppressions.json",
            Self::Private => ".bifrost/suppressions.private.json",
            Self::Local => ".bifrost/suppressions.local.json",
        }
    }
}

/// Identity and source coordinates copied from the current policy report.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PolicySuppressionFindingParams {
    pub(crate) policy_id: String,
    pub(crate) finding_id: String,
    pub(crate) path: String,
    pub(crate) identity_stability: String,
    pub(crate) policy_hash: String,
    #[serde(default)]
    pub(crate) source_uri: Option<Uri>,
    #[serde(default)]
    pub(crate) source_version: Option<i32>,
}

/// Request sent by the VS Code policy-results action.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PreparePolicySuppressionParams {
    pub(crate) report_root_uri: Uri,
    pub(crate) policy_document_uri: Uri,
    #[serde(default)]
    pub(crate) policy_document_version: Option<i32>,
    pub(crate) finding: PolicySuppressionFindingParams,
    pub(crate) destination: PolicySuppressionDestination,
    pub(crate) evaluation_date: PolicyEvaluationDate,
    #[serde(default)]
    pub(crate) reason: Option<String>,
    #[serde(default)]
    pub(crate) accepted_by: Option<String>,
    #[serde(default)]
    pub(crate) expires_at: Option<PolicyEvaluationDate>,
}

/// Canonical content plus the snapshot the client must still verify before it
/// applies a WorkspaceEdit.  The server never writes the destination itself.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PreparePolicySuppressionResult {
    pub(crate) document_uri: Uri,
    pub(crate) expected_version: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) expected_text: Option<String>,
    pub(crate) content: String,
    pub(crate) create: bool,
    pub(crate) source_preconditions: Vec<PolicySuppressionSourcePrecondition>,
}

/// Snapshot of every conventional suppression source read while preparing an
/// edit. A client must verify all of these snapshots before applying the edit:
/// the destination can be unchanged while a collision appears in another
/// source between preparation and application.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PolicySuppressionSourcePrecondition {
    pub(crate) path: String,
    pub(crate) uri: Uri,
    pub(crate) exists: bool,
    pub(crate) expected_version: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) expected_text: Option<String>,
}
