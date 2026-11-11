//! Shared completion evidence for product tool results.
use brokk_bifrost_analysis::analyzer::i_analyzer::{AnalyzerQueryScope, QueryReadIncomplete};
use schemars::JsonSchema;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ToolResultIncompleteReason {
    Cancelled,
    StructureUnavailable,
    AnalysisFailure,
    SemanticEvidenceIncomplete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct ToolResultIncomplete {
    pub reason: ToolResultIncompleteReason,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

pub fn query_read_incomplete(scope: &AnalyzerQueryScope<'_>) -> Vec<ToolResultIncomplete> {
    scope
        .read_completion()
        .err()
        .map(ToolResultIncomplete::from)
        .into_iter()
        .collect()
}

impl From<QueryReadIncomplete> for ToolResultIncomplete {
    fn from(reason: QueryReadIncomplete) -> Self {
        use ToolResultIncompleteReason as R;
        let (reason, detail) = match reason {
            QueryReadIncomplete::Cancelled => (R::Cancelled, None),
            QueryReadIncomplete::StructureUnavailable(file) => (
                R::StructureUnavailable,
                Some(format!("indexed syntax was unavailable for {file:?}")),
            ),
            QueryReadIncomplete::SemanticEvidenceGap(detail) => {
                (R::SemanticEvidenceIncomplete, Some(detail.into()))
            }
            QueryReadIncomplete::SemanticEvidenceUnavailable(detail)
            | QueryReadIncomplete::ArtifactUnavailable(detail) => {
                (R::AnalysisFailure, Some(detail.into()))
            }
            QueryReadIncomplete::StoreFailure(error) => (
                R::AnalysisFailure,
                Some(format!("indexed reads failed: {error}")),
            ),
        };
        Self { reason, detail }
    }
}

impl std::fmt::Display for ToolResultIncomplete {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reason = match self.reason {
            ToolResultIncompleteReason::Cancelled => "cancelled",
            ToolResultIncompleteReason::StructureUnavailable => "structure unavailable",
            ToolResultIncompleteReason::AnalysisFailure => "analysis failed",
            ToolResultIncompleteReason::SemanticEvidenceIncomplete => {
                "semantic evidence incomplete"
            }
        };
        formatter.write_str(reason)?;
        if let Some(detail) = &self.detail {
            write!(formatter, ": {detail}")?;
        }
        Ok(())
    }
}
