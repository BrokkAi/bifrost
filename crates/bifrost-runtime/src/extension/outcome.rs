use super::{
    ApiStability, ExtensionApiVersion, ExtensionCapabilityId, ExtensionLimitValues, SourceSpan,
    WorkspaceGeneration,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ExtensionCompletion {
    Complete,
    Ambiguous,
    Unknown,
    Unsupported { capability: ExtensionCapabilityId },
    Unproven,
    Truncated { limit: Box<str> },
    ExceededBudget { dimension: Box<str> },
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionDiagnostic {
    pub code: Box<str>,
    pub message: Box<str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<SourceSpan>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionWork {
    pub result_items: u64,
    pub result_bytes: u64,
    pub semantic_nodes: u64,
    pub semantic_edges: u64,
    pub source_bytes: u64,
    pub traversal_steps: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionResultMetadata {
    pub api: ExtensionApiVersion,
    pub operation: ExtensionCapabilityId,
    pub stability: ApiStability,
    pub generation: WorkspaceGeneration,
    pub diagnostics: Box<[ExtensionDiagnostic]>,
    pub work: ExtensionWork,
    pub limits: ExtensionLimitValues,
    pub provenance: Box<[Box<str>]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionOutcome<T> {
    pub completion: ExtensionCompletion,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<T>,
    pub metadata: ExtensionResultMetadata,
}
