use super::extractor::{ScanState, scan_file};
use super::inverted;
use super::resolver::{TargetSpec, VisibilityIndex};
use crate::analyzer::usages::common::{analyzed_files_for_language, language_for_file};
use crate::analyzer::usages::inverted_edges::{UsageEdgeWeights, UsageEdges};
use crate::analyzer::usages::model::{FuzzyResult, UsageHit, UsageHitSurface};
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::{UsageEdgeResolver, UsageQueryResolver, UsageScanScope};
use crate::analyzer::{CodeUnit, CppAnalyzer, IAnalyzer, Language, ProjectFile, resolve_analyzer};
use crate::hash::HashSet;
use std::collections::BTreeSet;

pub(crate) struct CppQueryResolver<'a> {
    cpp: &'a CppAnalyzer,
}

impl<'a> UsageQueryResolver<'a> for CppQueryResolver<'a> {
    fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        Some(Self {
            cpp: resolve_analyzer::<CppAnalyzer>(analyzer)?,
        })
    }

    fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        scan_scope: &UsageScanScope<'_>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        let Some(target) = overloads.first() else {
            return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
        };
        let Some(spec) = TargetSpec::from_targets(analyzer, overloads) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetShape("target shape is unsupported"),
                "CppUsageGraphStrategy",
            );
        };

        let candidate_files = scan_scope.candidate_files();
        let mut files: HashSet<ProjectFile> = candidate_files
            .iter()
            .filter(|file| language_for_file(file) == Language::Cpp)
            .cloned()
            .collect();
        if scan_scope.allows(target.source()) {
            files.insert(target.source().clone());
        }
        let visibility = VisibilityIndex::build_with_cancellation(
            self.cpp,
            analyzer,
            &files,
            scan_scope.cancellation(),
        );

        let mut hits: BTreeSet<UsageHit> = BTreeSet::new();
        let mut unproven_hits: BTreeSet<UsageHit> = BTreeSet::new();
        let mut raw_match_count = 0usize;
        let mut limit_exceeded = false;
        let mut state = ScanState {
            max_usages,
            hits: &mut hits,
            unproven_hits: &mut unproven_hits,
            raw_match_count: &mut raw_match_count,
            limit_exceeded: &mut limit_exceeded,
        };

        for file in files {
            if scan_scope.is_cancelled() {
                break;
            }
            scan_file(analyzer, &visibility, &file, &spec, &mut state);
            if *state.limit_exceeded {
                break;
            }
        }

        let external_hit_count = hits
            .iter()
            .filter(|hit| hit.kind.included_in(UsageHitSurface::ExternalUsages))
            .count();
        if limit_exceeded || external_hit_count > max_usages {
            return GraphUsageOutcome::Resolved(FuzzyResult::TooManyCallsites {
                short_name: target.short_name().to_string(),
                total_callsites: external_hit_count,
                limit: max_usages,
                sample_hits: hits,
            });
        }

        GraphUsageOutcome::Resolved(FuzzyResult::success_with_unproven(
            target.clone(),
            hits,
            unproven_hits,
        ))
    }
}

pub(crate) struct CppEdgeResolver<'a> {
    cpp: &'a CppAnalyzer,
    files: Vec<ProjectFile>,
}

impl<'a> UsageEdgeResolver<'a> for CppEdgeResolver<'a> {
    fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        let cpp = resolve_analyzer::<CppAnalyzer>(analyzer)?;
        let files = analyzed_files_for_language(analyzer, Language::Cpp);
        Some(Self { cpp, files })
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
        // Resolution honors each caller file's include closure, so the visibility
        // index is seeded with every in-scope caller file as a root (mirroring the
        // forward scan, which builds it from the query's candidate files). Built here
        // rather than at construction so the trait's `try_new` needs no `keep_file`.
        let roots: HashSet<ProjectFile> = self
            .files
            .iter()
            .filter(|file| keep_file(file))
            .cloned()
            .collect();
        let visibility = VisibilityIndex::build(self.cpp, analyzer, &roots);
        inverted::build_cpp_edges(analyzer, &self.files, &visibility, nodes, keep_file)
    }

    fn build_edge_weights<F>(
        &self,
        analyzer: &dyn IAnalyzer,
        nodes: &HashSet<String>,
        keep_file: F,
    ) -> UsageEdgeWeights
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        let roots: HashSet<ProjectFile> = self
            .files
            .iter()
            .filter(|file| keep_file(file))
            .cloned()
            .collect();
        let visibility = VisibilityIndex::build(self.cpp, analyzer, &roots);
        inverted::build_cpp_edges(analyzer, &self.files, &visibility, nodes, keep_file)
    }
}
