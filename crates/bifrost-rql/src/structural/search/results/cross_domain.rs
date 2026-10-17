//! The public cross-domain row (#3284).

use super::*;
use brokk_bifrost_core::analyzer::configuration::ConfigurationResolutionResult;

/// One row of a registered cross-domain operator.
///
/// `domain` discriminates the row. A `correlated` row (from `correlate`)
/// carries one code row and one configuration fact that the named `relation`
/// proved related, the `key` that related them, and a `binding` of `unique`
/// or `ambiguous`. A `code` or `configuration` row (from `require_both`)
/// carries exactly one contributing input row and states nothing about any
/// row of the other domain. A dependency-configuration relation also preserves
/// an unpaired `code` witness when configuration cannot establish mitigation.
/// Its `mitigated` flag never claims runtime safety; original dependency identity,
/// reviewed mapping and bounded effective evidence travel independently.
///
/// `code` is a reference to the code row: its own `result_type`, exact
/// location, and the identity fields its family carries. `configuration` is
/// the whole authored fact. `code_id` is a detail-independent identity of the
/// code row; `configuration_id` equals the `id` of the `configuration_fact`
/// row, so a policy can join on it. `path` and `range` anchor the row: the code row
/// when one is carried, otherwise the configuration fact. `range` is absent
/// only when the anchor row has no source region of its own (a `file` row).
#[cfg_attr(feature = "query-result-fixtures", derive(Default))]
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct CodeQueryCrossDomain {
    pub id: String,
    pub operator: &'static str,
    pub domain: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relation: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<CodeQueryResultRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configuration_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configuration_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configuration: Option<Box<CodeQueryConfigurationFact>>,
    /// Present for dependency-configuration witnesses. False means mitigation
    /// was not proved, including unsupported or incomplete evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitigated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dependency_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mapping_id: Option<String>,
    /// Canonical #3275 proof, completeness, ordered contributions and edges.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_configuration: Option<ConfigurationResolutionResult>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub configuration_contributors: Vec<CodeQueryConfigurationFact>,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub range: Option<CodeQueryRange>,
}
