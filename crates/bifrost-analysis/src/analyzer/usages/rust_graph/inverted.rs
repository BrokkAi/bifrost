//! The whole-workspace inverted pass's fan-out for Rust.
//!
//! The scan itself is [`brokk_bifrost_rust::graph::inverted::scan_file`]. What
//! stays here is the shared driver -- `build_edge_output`'s parallel walk plus
//! `parse_and_collect`'s on-demand parsing -- the downcast that produces the two
//! sources, and the one `IAnalyzer::global_usage_definition_index` call.

use crate::analyzer::usages::inverted_edges::{
    UsageEdgeBuildOutput, build_edge_output, parse_and_collect,
};
use crate::analyzer::{CodeUnitIndex, IAnalyzer, ProjectFile, RustAnalyzer};
use crate::hash::HashSet;
use brokk_bifrost_rust::graph::inverted::{RustSeedsCache, scan_file};

/// Build the whole Rust `caller -> callee` edge set in a single inverted pass.
pub(super) fn build_rust_edges<Output, F>(
    analyzer: &dyn IAnalyzer,
    rust: &RustAnalyzer,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Output
where
    Output: UsageEdgeBuildOutput<String>,
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let files: Vec<ProjectFile> = rust.get_analyzed_files().into_iter().collect();
    let support = analyzer.global_usage_definition_index();
    let language = tree_sitter_rust::LANGUAGE.into();
    let keep_file = &keep_file;
    let seeds_cache = RustSeedsCache::default();
    let seeds_cache = &seeds_cache;
    build_edge_output(&files, keep_file, |file| {
        let refs = rust.reference_context_of_with_progress(file, &|| keep_file(file))?;
        parse_and_collect(analyzer, file, nodes, &language, |input| {
            scan_file(
                rust,
                &support,
                seeds_cache,
                file,
                refs.clone(),
                input,
                &|| keep_file(file),
            )
        })
    })
}
