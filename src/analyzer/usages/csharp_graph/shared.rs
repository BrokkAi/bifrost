use super::extractor::{ScanState, scan_file};
use super::inverted;
use super::resolver::{TargetKind, TargetSpec, resolve_csharp_analyzer};
use crate::analyzer::usages::common::language_for_file;
use crate::analyzer::usages::inverted_edges::UsageEdges;
use crate::analyzer::usages::model::{FuzzyResult, UsageHit};
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::{CSharpAnalyzer, CodeUnit, IAnalyzer, Language, ProjectFile};
use crate::hash::HashSet;
use std::collections::BTreeSet;

pub(crate) struct CSharpQueryResolver<'a> {
    csharp: &'a CSharpAnalyzer,
}

impl<'a> CSharpQueryResolver<'a> {
    pub(crate) fn new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        Some(Self {
            csharp: resolve_csharp_analyzer(analyzer)?,
        })
    }

    pub(crate) fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        target: &CodeUnit,
        candidate_files: &HashSet<ProjectFile>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        let Some(spec) = TargetSpec::from_target(analyzer, target) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetShape("target shape is unsupported"),
                "CSharpUsageGraphStrategy",
            );
        };

        let files: HashSet<ProjectFile> = candidate_files
            .iter()
            .filter(|file| language_for_file(file) == Language::CSharp)
            .cloned()
            .chain(std::iter::once(target.source().clone()))
            .collect();

        let mut hits: BTreeSet<UsageHit> = BTreeSet::new();
        let mut saw_unproven_match = false;
        let mut limit_exceeded = false;
        let mut state = ScanState {
            max_usages,
            hits: &mut hits,
            saw_unproven_match: &mut saw_unproven_match,
            limit_exceeded: &mut limit_exceeded,
        };
        for file in files {
            scan_file(self.csharp, analyzer, &file, &spec, &mut state);
            if *state.limit_exceeded {
                break;
            }
        }

        if saw_unproven_match && spec.kind != TargetKind::Type {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsafeInference("no proven structured hits"),
                "CSharpUsageGraphStrategy",
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

pub(crate) struct CSharpEdgeResolver<'a> {
    csharp: &'a CSharpAnalyzer,
    files: Vec<ProjectFile>,
}

impl<'a> CSharpEdgeResolver<'a> {
    pub(crate) fn new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        let csharp = resolve_csharp_analyzer(analyzer)?;
        let files: Vec<ProjectFile> = analyzer
            .project()
            .analyzable_files(Language::CSharp)
            .ok()?
            .into_iter()
            .collect();
        Some(Self { csharp, files })
    }

    pub(crate) fn build_edges<F>(
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
