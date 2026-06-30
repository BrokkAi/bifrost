mod extractor;
mod hits;
mod inverted;
mod resolver;

use crate::analyzer::usages::common::language_for_target;
use crate::analyzer::usages::inverted_edges::UsageEdges;
use crate::analyzer::usages::model::{FuzzyResult, ReferenceGraphResult};
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::rust_graph::extractor::{
    build_rust_graph_for_files, effective_scan_files, scan_files_for_member_target,
    scan_files_for_target,
};
use crate::analyzer::usages::rust_graph::resolver::{
    infer_graph_seeds, is_graph_visible_member_target, is_member_target,
    supports_same_file_local_scan, unresolved_external_frontier_specifiers,
};
use crate::analyzer::usages::traits::{UsageAnalyzer, UsageEdgeResolver, UsageQueryResolver};
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile, RustAnalyzer, resolve_analyzer};
use crate::hash::HashSet;
use std::collections::BTreeSet;

/// Build the whole Rust `caller -> callee` edge set in a single inverted pass
/// over the workspace (see [`inverted`]). Returns `None` when there are no Rust
/// files. `nodes`/`keep_file` mirror the Go builder.
///
/// Both usage paths resolve references through analyzer state: per-reference name
/// resolution via the cached [`crate::analyzer::RustReferenceContext`], and the
/// forward path's re-export seeds + importer narrowing via the analyzer's
/// `usage_*` index (`RustAnalyzer::usage_seeds` / `usage_importers` /
/// `usage_binding_names`).
pub(crate) fn build_rust_usage_edges<F>(
    analyzer: &dyn IAnalyzer,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Option<UsageEdges>
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let resolver = RustEdgeResolver::try_new(analyzer)?;
    Some(resolver.build_edges(analyzer, nodes, keep_file))
}

pub(crate) struct RustQueryResolver<'a> {
    rust: &'a RustAnalyzer,
}

impl<'a> UsageQueryResolver<'a> for RustQueryResolver<'a> {
    fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        Some(Self {
            rust: resolve_analyzer::<RustAnalyzer>(analyzer)?,
        })
    }

    fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        candidate_files: &HashSet<ProjectFile>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        let Some(target) = overloads.first() else {
            return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
        };
        let rust = self.rust;

        let hits = if supports_same_file_local_scan(rust, target) {
            let scan_files: HashSet<ProjectFile> = [target.source().clone()].into_iter().collect();
            let graph = build_rust_graph_for_files(scan_files.clone());
            scan_files_for_target(analyzer, rust, &graph, scan_files, target, None)
        } else if is_member_target(rust, target) {
            let seeds = infer_graph_seeds(rust, target);
            if seeds.is_empty() {
                return GraphUsageOutcome::fallback_safe(
                    target.fq_name(),
                    GraphFailureReason::NoGraphSeed("no export seed resolved"),
                    "RustExportUsageGraphStrategy",
                );
            }
            if !is_graph_visible_member_target(rust, target) {
                return GraphUsageOutcome::Resolved(FuzzyResult::success(
                    target.clone(),
                    BTreeSet::new(),
                ));
            }
            let scan_files = effective_scan_files(rust, candidate_files, target, &seeds);
            let graph = build_rust_graph_for_files(scan_files.clone());
            scan_files_for_member_target(analyzer, &graph, rust, scan_files, target, &seeds)
        } else {
            let seeds = infer_graph_seeds(rust, target);
            if seeds.is_empty() {
                return GraphUsageOutcome::fallback_safe(
                    target.fq_name(),
                    GraphFailureReason::NoGraphSeed("no export seed resolved"),
                    "RustExportUsageGraphStrategy",
                );
            }
            let scan_files = effective_scan_files(rust, candidate_files, target, &seeds);
            let graph = build_rust_graph_for_files(scan_files.clone());
            scan_files_for_target(analyzer, rust, &graph, scan_files, target, Some(&seeds))
        };

        let hits: BTreeSet<_> = hits
            .into_iter()
            .filter(|hit| &hit.enclosing != target)
            .collect();

        if hits.len() > max_usages {
            return GraphUsageOutcome::Resolved(FuzzyResult::TooManyCallsites {
                short_name: target.short_name().to_string(),
                total_callsites: hits.len(),
                limit: max_usages,
            });
        }

        GraphUsageOutcome::Resolved(FuzzyResult::success(target.clone(), hits))
    }
}

pub(crate) struct RustEdgeResolver<'a> {
    rust: &'a RustAnalyzer,
}

impl<'a> UsageEdgeResolver<'a> for RustEdgeResolver<'a> {
    fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        Some(Self {
            rust: resolve_analyzer::<RustAnalyzer>(analyzer)?,
        })
    }

    fn build_edges<F>(
        &self,
        analyzer: &dyn IAnalyzer,
        nodes: &HashSet<String>,
        keep_file: F,
    ) -> UsageEdges
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        inverted::build_rust_edges(analyzer, self.rust, nodes, keep_file)
    }
}

#[derive(Default)]
pub struct RustExportUsageGraphStrategy;

impl RustExportUsageGraphStrategy {
    pub fn new() -> Self {
        Self
    }

    pub fn can_handle(target: &CodeUnit) -> bool {
        language_for_target(target) == Language::Rust
    }

    pub fn find_export_usages(
        analyzer: &RustAnalyzer,
        defining_file: &ProjectFile,
        export_name: &str,
        query_target: Option<&CodeUnit>,
        candidate_files: &HashSet<ProjectFile>,
        max_usages: usize,
    ) -> ReferenceGraphResult {
        let external_frontier_specifiers =
            unresolved_external_frontier_specifiers(analyzer, defining_file, export_name);
        let hits = query_target
            .map(|target| {
                Self::new()
                    .find_usages(
                        analyzer,
                        std::slice::from_ref(target),
                        candidate_files,
                        max_usages,
                    )
                    .all_hits()
            })
            .unwrap_or_default();

        ReferenceGraphResult {
            hits,
            external_frontier_specifiers,
        }
    }

    pub(crate) fn find_graph_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        candidate_files: &HashSet<ProjectFile>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        if overloads.is_empty() {
            return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
        }

        let target = &overloads[0];
        if language_for_target(target) != Language::Rust {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetLanguage("target is not Rust"),
                "RustExportUsageGraphStrategy",
            );
        }

        let Some(resolver) = RustQueryResolver::try_new(analyzer) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::MissingAnalyzerCapability(
                    "analyzer does not expose RustAnalyzer",
                ),
                "RustExportUsageGraphStrategy",
            );
        };

        resolver.find_usages(analyzer, overloads, candidate_files, max_usages)
    }
}

impl UsageAnalyzer for RustExportUsageGraphStrategy {
    fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        candidate_files: &HashSet<ProjectFile>,
        max_usages: usize,
    ) -> FuzzyResult {
        self.find_graph_usages(analyzer, overloads, candidate_files, max_usages)
            .into_fuzzy_result()
    }
}
