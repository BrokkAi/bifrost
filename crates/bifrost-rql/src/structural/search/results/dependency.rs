use super::*;

/// A static dependency file fact. Ownership and exact version never imply
/// enabled features, compilation, installation, loading or exploitability.
#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct CodeQueryDependencyEvidence {
    pub id: String,
    pub path: String,
    pub ecosystem: String,
    pub package: String,
    pub evidence_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_requirement: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exact_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locator: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declared_by: Option<String>,
    pub scope: String,
    pub conditions: Vec<CodeQueryDependencyCondition>,
    pub source_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub range: Option<CodeQueryRange>,
    pub start_byte: usize,
    pub end_byte: usize,
    pub complete: bool,
}
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct CodeQueryDependencyCondition {
    pub kind: String,
    pub value: String,
}
