//! Product-facing code intelligence, quality reports, and workspace tools.

pub mod blast_radius;
pub mod code_quality;
pub mod cyclomatic_complexity_diff;
pub mod diff_analysis;
pub mod diff_scoring;
pub mod file_tools;
pub mod model_context;
pub mod relevance;
pub mod searchtools;
pub mod searchtools_render;
pub mod summary;
pub mod symbol_rename;

pub use summary::{RenderedSummary, SummaryInput, summarize_inputs};

#[cfg(any(test, feature = "test-support"))]
pub mod native_resolution_test_support {
    pub use crate::blast_radius::{
        SelectedMissingTestsTelemetry, missing_tests_at_root_with_selected_inverse_index,
    };
    pub use crate::relevance::{SelectedExactRelevanceTelemetry, SelectedExactUsageGraphLifecycle};
    pub use crate::searchtools::{
        MostRelevantFile, MostRelevantFilesIncompleteReason, MostRelevantFilesParams,
        MostRelevantFilesRankingMode, MostRelevantFilesResult,
        most_relevant_files_with_selected_exact_graph_builder,
    };
    pub use crate::searchtools::{
        SelectedUsageGraphBuildOutcome, SelectedUsageGraphTelemetry,
        build_selected_unscoped_usage_graph,
    };
    pub use brokk_bifrost_analysis::native_resolution_test_support::*;
}

#[cfg(test)]
mod engine_tests;

// Engine fixture paths used by relocated unit-test modules.
#[cfg(test)]
use brokk_bifrost_analysis::*;

mod language_registry;

#[cfg(test)]
use brokk_bifrost_rust_analysis::analyzer;
