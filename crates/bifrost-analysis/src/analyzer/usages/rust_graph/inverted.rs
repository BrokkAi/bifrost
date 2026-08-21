//! The whole-workspace inverted pass's fan-out for Rust.
//!
//! The scan itself is [`brokk_bifrost_rust::graph::inverted::scan_file`]. What
//! stays here is the shared driver -- `build_edge_output`'s parallel walk plus
//! `parse_and_collect`'s on-demand parsing -- the downcast that produces the two
//! sources, and the request-scoped bounded definition lookup.

use crate::analyzer::usages::inverted_edges::{
    UsageEdgeBuildOutput, build_edge_output, parse_and_collect,
};
use crate::analyzer::usages::parsed_tree::ParseSpec;
use crate::analyzer::{AnalyzerQueryScope, QueryScope};
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
    // The pass's request boundary; nested inside any caller-owned scope
    // (issue #2414 step 3).
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    let files: Vec<ProjectFile> = rust.get_analyzed_files().into_iter().collect();
    let support =
        crate::analyzer::AnalyzerDefinitionLookup::new(analyzer, crate::analyzer::Language::None);
    let language = tree_sitter_rust::LANGUAGE.into();
    let keep_file = &keep_file;
    let seeds_cache = RustSeedsCache::default();
    let seeds_cache = &seeds_cache;
    build_edge_output(&files, keep_file, |file| {
        keep_file(file).then_some(())?;
        let refs = rust.reference_context_of_while(token, file, || keep_file(file));
        parse_and_collect(
            analyzer,
            file,
            nodes,
            ParseSpec::whole(&language),
            |input| {
                scan_file(rust, &support, seeds_cache, file, refs, input, &|| {
                    keep_file(file)
                })
            },
        )
    })
}
