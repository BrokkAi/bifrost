use super::extractor::{ScanState, scan_file};
use super::inverted;
use super::jvm_scala::scan_scala_files_for_java_type;
use super::resolver::TargetSpec;
use crate::analyzer::usages::common::{analyzed_files_for_language, language_for_file};
use crate::analyzer::usages::inverted_edges::UsageEdges;
use crate::analyzer::usages::model::{FuzzyResult, UsageHit};
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::{UsageEdgeResolver, UsageQueryResolver, UsageScanScope};
use crate::analyzer::{CodeUnit, IAnalyzer, JavaAnalyzer, Language, ProjectFile, resolve_analyzer};
use crate::hash::HashSet;
use std::collections::BTreeSet;

pub(crate) struct JavaQueryResolver<'a> {
    java: &'a JavaAnalyzer,
}

impl<'a> UsageQueryResolver<'a> for JavaQueryResolver<'a> {
    fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        Some(Self {
            java: resolve_analyzer::<JavaAnalyzer>(analyzer)?,
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
        let Some(spec) = TargetSpec::from_target(self.java, target) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetShape("target shape is unsupported"),
                "JavaUsageGraphStrategy",
            );
        };

        let candidate_files = scan_scope.candidate_files();
        let mut files: HashSet<ProjectFile> = candidate_files
            .iter()
            .filter(|file| language_for_file(file) == Language::Java)
            .cloned()
            .collect();
        if scan_scope.allows(target.source()) {
            files.insert(target.source().clone());
        }

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
            scan_file(self.java, analyzer, &file, &spec, &mut state);
            if *state.limit_exceeded {
                break;
            }
        }
        if !scan_scope.is_cancelled() {
            scan_scala_files_for_java_type(analyzer, candidate_files, &spec, &mut state);
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

pub(crate) struct JavaEdgeResolver<'a> {
    java: &'a JavaAnalyzer,
    files: Vec<ProjectFile>,
}

impl<'a> UsageEdgeResolver<'a> for JavaEdgeResolver<'a> {
    fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        let java = resolve_analyzer::<JavaAnalyzer>(analyzer)?;
        let files = analyzed_files_for_language(analyzer, Language::Java);
        Some(Self { java, files })
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
        inverted::build_java_edges(analyzer, self.java, &self.files, nodes, keep_file)
    }
}
