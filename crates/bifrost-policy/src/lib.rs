//! Versioned static-analysis policy authoring, loading, evaluation, and reporting.
//!
//! Internal implementation detail of `brokk-bifrost`; no stability guarantees --
//! depend on `brokk-bifrost` instead.

pub(crate) fn fmt_policy_json_decode_error(
    formatter: &mut std::fmt::Formatter<'_>,
    document: &str,
    message: &str,
    line: usize,
    column: usize,
) -> std::fmt::Result {
    write!(
        formatter,
        "invalid {document} JSON at line {line}, column {column}: {message}"
    )
}

pub(crate) fn is_over_byte_limit(value: &str, max_bytes: usize) -> bool {
    value.len() > max_bytes
}

pub(crate) fn is_over_u64_byte_limit(value: &str, max_bytes: u64) -> bool {
    u64::try_from(value.len()).unwrap_or(u64::MAX) > max_bytes
}

macro_rules! impl_policy_analysis_type {
    ($analysis:ident) => {
        impl $analysis {
            pub const fn analysis_type(&self) -> PolicyAnalysisType {
                match self {
                    Self::Match { .. } => PolicyAnalysisType::Match,
                    Self::Taint { .. } => PolicyAnalysisType::Taint,
                    Self::Typestate { .. } => PolicyAnalysisType::Typestate,
                    Self::Assertion { .. } => PolicyAnalysisType::Assertion,
                    Self::Flow { .. } => PolicyAnalysisType::Flow,
                }
            }
        }
    };
}

pub(crate) use impl_policy_analysis_type;

macro_rules! impl_finding_anchor_stability {
    ($anchor:ident) => {
        impl $anchor {
            pub const fn stability(&self) -> $crate::finding_identity::FindingIdentityStability {
                match self {
                    Self::Strong(_) => $crate::finding_identity::FindingIdentityStability::Strong,
                    Self::Weak(_) => $crate::finding_identity::FindingIdentityStability::Weak,
                }
            }
        }
    };
}

pub(crate) use impl_finding_anchor_stability;

macro_rules! impl_policy_source_error {
    ($error:ident) => {
        impl std::error::Error for $error {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                match self {
                    Self::Path(error) => Some(error),
                    Self::TooLong { .. } => None,
                }
            }
        }
    };
}

pub(crate) use impl_policy_source_error;

mod assertion_policy;
mod baseline;
mod budget;
mod builtin;
mod canonical;
mod canonical_loaded;
mod catalog;
mod classification;
mod composition;
mod coordinator;
mod cvss;
mod definition;
mod display_path;
mod evaluator;
mod explain;
mod finding;
mod finding_identity;
mod format;
mod future_evidence;
mod identity;
mod loading;
mod locator;
mod parallel;
mod projection;
mod registry;
mod relational;
mod render;
mod report;
mod resolved;
mod retained;
pub mod schema;
mod scope;
mod selector_compiler;
mod semantic_identity;
mod serde_utils;
mod source;
mod suppression;
mod taint_compose_provider;
mod taint_policy;
mod typestate_policy;
mod unit_execution;
mod units;
mod witness_projection;

pub use render::is_bidi_control;

/// Whether a serialized boolean is at its default, for the `skip_serializing_if`
/// of every optional flag in this crate's report model.
const fn is_false(value: &bool) -> bool {
    !*value
}

const fn is_zero(value: &u64) -> bool {
    *value == 0
}

pub(crate) fn serialize_display_value<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: std::fmt::Display,
    S: serde::Serializer,
{
    serializer.collect_str(value)
}

pub(crate) fn fmt_limit_error<F, H, V>(
    formatter: &mut std::fmt::Formatter<'_>,
    field: &F,
    hard_maximum: &H,
    value: &V,
) -> std::fmt::Result
where
    F: std::fmt::Display,
    H: std::fmt::Display,
    V: std::fmt::Display,
{
    write!(
        formatter,
        "{} must be from 1 through {}, found {}",
        field, hard_maximum, value
    )
}

pub(crate) const fn within_policy_limit(value: usize, hard_maximum: usize) -> bool {
    value != 0 && value <= hard_maximum
}

#[cfg(test)]
mod adapter_seam_tests;
#[cfg(test)]
mod flow_policy_tests;
#[cfg(test)]
#[path = "../../../test-support/inline_project.rs"]
mod inline_project;
#[cfg(test)]
#[path = "../../../test-support/policy_suppressions.rs"]
mod policy_suppressions;
#[cfg(test)]
mod store_policy_tests;
#[cfg(test)]
mod test_support;

pub use assertion_policy::*;
pub use baseline::*;
pub use brokk_bifrost_analysis::schema_version::{SchemaVersionOrigin, SchemaVersionResolution};
pub use brokk_bifrost_analysis::workspace_document::{WorkspaceDocumentError, WorkspacePathError};
pub use budget::*;
pub use builtin::*;
pub use canonical::InlineLocalSemanticProjectionError;
pub use catalog::*;
pub use classification::*;
pub use coordinator::*;
pub use cvss::*;
pub use definition::*;
pub use evaluator::*;
pub use explain::*;
pub use finding::*;
pub use finding_identity::*;
pub use format::*;
pub use future_evidence::*;
pub use identity::*;
pub use parallel::*;
pub use registry::*;
pub use relational::*;
pub use render::*;
pub use report::*;
pub use resolved::*;
pub use scope::*;
pub use source::rqlp_source_completion_at;
pub use source::*;
pub use suppression::*;
pub use units::*;
// The retained plan/report pair and its phase metrics are produced by the taint
// engine, not by policy. They are re-exported here because they are part of this
// crate's public authoring and reporting surface.
pub use brokk_bifrost_flow::taint::{ProductionTaintAnalysisResult, ProductionTaintPhaseMetrics};
