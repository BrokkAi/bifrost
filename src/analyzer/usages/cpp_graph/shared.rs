use super::extractor::{ScanState, scan_file};
use super::inverted;
use super::resolver::{TargetSpec, VisibilityIndex, collect_include_closure};
use crate::analyzer::usages::common::language_for_file;
use crate::analyzer::usages::inverted_edges::UsageEdges;
use crate::analyzer::usages::model::{FuzzyResult, UsageHit};
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::{UsageEdgeResolver, UsageQueryResolver};
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
        candidate_files: &HashSet<ProjectFile>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        let Some(target) = overloads.first() else {
            return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
        };
        let Some(spec) = TargetSpec::from_target(analyzer, target) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetShape("target shape is unsupported"),
                "CppUsageGraphStrategy",
            );
        };

        let files: HashSet<ProjectFile> = candidate_files
            .iter()
            .filter(|file| language_for_file(file) == Language::Cpp)
            .cloned()
            .chain(std::iter::once(target.source().clone()))
            .collect();
        let visibility = VisibilityIndex::build(self.cpp, analyzer, &files);

        let mut hits: BTreeSet<UsageHit> = BTreeSet::new();
        let mut saw_unproven_match = false;
        let mut raw_match_count = 0usize;
        let mut limit_exceeded = false;
        let mut state = ScanState {
            max_usages,
            hits: &mut hits,
            saw_unproven_match: &mut saw_unproven_match,
            raw_match_count: &mut raw_match_count,
            limit_exceeded: &mut limit_exceeded,
        };

        for file in files {
            scan_file(analyzer, &visibility, &file, &spec, &mut state);
            if *state.limit_exceeded {
                break;
            }
        }

        if saw_unproven_match {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsafeInference("no proven structured hits"),
                "CppUsageGraphStrategy",
            );
        }

        if limit_exceeded || hits.len() > max_usages {
            return GraphUsageOutcome::Resolved(FuzzyResult::TooManyCallsites {
                short_name: target.short_name().to_string(),
                total_callsites: hits.len(),
                limit: max_usages,
            });
        }

        GraphUsageOutcome::Resolved(FuzzyResult::success(target.clone(), hits))
    }
}

pub(crate) struct CppEdgeResolver<'a> {
    cpp: &'a CppAnalyzer,
    files: Vec<ProjectFile>,
}

impl<'a> UsageEdgeResolver<'a> for CppEdgeResolver<'a> {
    fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        let cpp = resolve_analyzer::<CppAnalyzer>(analyzer)?;
        let files: Vec<ProjectFile> = analyzer
            .project()
            .analyzable_files(Language::Cpp)
            .ok()?
            .into_iter()
            .collect();
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
        let roots: HashSet<ProjectFile> = {
            let mut roots = HashSet::default();
            for file in self.files.iter().filter(|file| keep_file(file)) {
                collect_include_closure(self.cpp, analyzer, file, &mut roots);
            }
            roots
        };
        let visibility = VisibilityIndex::build(self.cpp, analyzer, &roots);
        inverted::build_cpp_edges(analyzer, &self.files, &visibility, nodes, keep_file)
    }
}
