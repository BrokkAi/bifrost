use super::extractor::{ScanState, scan_file};
use super::inverted;
use super::resolver::TargetSpec;
use crate::analyzer::usages::common::{analyzed_files_for_language, language_for_file};
use crate::analyzer::usages::inverted_edges::UsageEdges;
use crate::analyzer::usages::model::{FuzzyResult, UsageHit};
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::{UsageEdgeResolver, UsageQueryResolver, UsageScanScope};
use crate::analyzer::{
    CSharpAnalyzer, CodeUnit, IAnalyzer, Language, ProjectFile, resolve_analyzer,
};
use crate::hash::HashSet;
use std::collections::BTreeSet;

pub(crate) struct CSharpQueryResolver<'a> {
    csharp: &'a CSharpAnalyzer,
}

impl<'a> UsageQueryResolver<'a> for CSharpQueryResolver<'a> {
    fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        Some(Self {
            csharp: resolve_analyzer::<CSharpAnalyzer>(analyzer)?,
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
        let Some(spec) = TargetSpec::from_target(analyzer, target) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetShape("target shape is unsupported"),
                "CSharpUsageGraphStrategy",
            );
        };

        let candidate_files = scan_scope.candidate_files();
        let mut files: HashSet<ProjectFile> = candidate_files
            .iter()
            .filter(|file| language_for_file(file) == Language::CSharp)
            .cloned()
            .collect();
        if scan_scope.allows(target.source()) {
            files.insert(target.source().clone());
        }

        let mut hits: BTreeSet<UsageHit> = BTreeSet::new();
        let mut unproven_hits: BTreeSet<UsageHit> = BTreeSet::new();
        let mut limit_exceeded = false;
        let mut state = ScanState {
            max_usages,
            hits: &mut hits,
            unproven_hits: &mut unproven_hits,
            limit_exceeded: &mut limit_exceeded,
        };
        for file in files {
            if scan_scope.is_cancelled() {
                break;
            }
            scan_file(self.csharp, analyzer, &file, &spec, &mut state);
            if *state.limit_exceeded {
                break;
            }
        }

        if limit_exceeded || hits.len() > max_usages {
            return GraphUsageOutcome::Resolved(FuzzyResult::TooManyCallsites {
                short_name: target.short_name().to_string(),
                total_callsites: hits.len(),
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

pub(crate) struct CSharpEdgeResolver<'a> {
    csharp: &'a CSharpAnalyzer,
    files: Vec<ProjectFile>,
}

impl<'a> UsageEdgeResolver<'a> for CSharpEdgeResolver<'a> {
    fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        let csharp = resolve_analyzer::<CSharpAnalyzer>(analyzer)?;
        let files = analyzed_files_for_language(analyzer, Language::CSharp);
        Some(Self { csharp, files })
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
        inverted::build_csharp_edges(analyzer, self.csharp, &self.files, nodes, keep_file)
    }
}
