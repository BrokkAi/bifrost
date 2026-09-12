//! The public configuration-fact row (#3277).

use super::*;

/// One authored configuration-document fact.
///
/// `fact_id`, `parent_id`, and `value_id` are the document-scoped stable ids
/// the core model derives from format, node kind, and route, so an unrelated
/// sibling edit cannot move them. `id` scopes that same identity to the
/// workspace row. `route` renders the exact ordered segments (key texts with
/// `#<occurrence>` only on duplicates, zero-based indexes as integers) as a
/// JSON array; it is a rendering, and `occurrence`/`index` carry the exact
/// numbers.
#[derive(Debug, Clone, Serialize)]
pub struct CodeQueryConfigurationFact {
    pub id: String,
    pub fact_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_id: Option<String>,
    pub path: String,
    pub format: &'static str,
    pub node_kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scalar_kind: Option<&'static str>,
    pub provenance: &'static str,
    pub completeness: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub occurrence: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<u32>,
    pub route: String,
    pub ordinal: u32,
    pub range: CodeQueryRange,
    pub start_byte: usize,
    pub end_byte: usize,
}
