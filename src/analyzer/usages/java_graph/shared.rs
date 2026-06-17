use super::extractor::{ScanState, scan_file};
use super::inverted;
use super::jvm_scala::scan_scala_files_for_java_type;
use super::resolver::{TargetSpec, resolve_java_analyzer};
use crate::analyzer::usages::common::language_for_file;
use crate::analyzer::usages::inverted_edges::UsageEdges;
use crate::analyzer::usages::model::{FuzzyResult, UsageHit};
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::{CodeUnit, IAnalyzer, JavaAnalyzer, Language, ProjectFile};
use crate::hash::HashSet;
use std::collections::BTreeSet;

pub(crate) struct JavaQueryResolver<'a> {
    java: &'a JavaAnalyzer,
}

impl<'a> JavaQueryResolver<'a> {
    pub(crate) fn new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        Some(Self {
            java: resolve_java_analyzer(analyzer)?,
        })
    }

    pub(crate) fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        target: &CodeUnit,
        candidate_files: &HashSet<ProjectFile>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        let Some(spec) = TargetSpec::from_target(self.java, target) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetShape("target shape is unsupported"),
                "JavaUsageGraphStrategy",
            );
        };

        let files: HashSet<ProjectFile> = candidate_files
            .iter()
            .filter(|file| language_for_file(file) == Language::Java)
            .cloned()
            .chain(std::iter::once(target.source().clone()))
            .collect();

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
            scan_file(self.java, analyzer, &file, &spec, &mut state);
            if *state.limit_exceeded {
                break;
            }
        }
        scan_scala_files_for_java_type(analyzer, candidate_files, &spec, &mut state);

        if hits.is_empty() && saw_unproven_match {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsafeInference("no proven structured hits"),
                "JavaUsageGraphStrategy",
            );
        }

        if hits.is_empty() {
            return GraphUsageOutcome::Resolved(FuzzyResult::success(
                target.clone(),
                BTreeSet::new(),
            ));
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

pub(crate) struct JavaEdgeResolver<'a> {
    java: &'a JavaAnalyzer,
    files: Vec<ProjectFile>,
}

impl<'a> JavaEdgeResolver<'a> {
    pub(crate) fn new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        let java = resolve_java_analyzer(analyzer)?;
        let files: Vec<ProjectFile> = analyzer
            .project()
            .analyzable_files(Language::Java)
            .ok()?
            .into_iter()
            .collect();
        Some(Self { java, files })
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
        inverted::build_java_edges(analyzer, self.java, &self.files, nodes, keep_file)
    }
}
