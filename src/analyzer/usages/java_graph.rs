mod extractor;
mod hits;
mod resolver;

use crate::analyzer::common::language_for_target;
use crate::analyzer::usages::java_graph::extractor::{ScanState, scan_file};
use crate::analyzer::usages::java_graph::resolver::{TargetSpec, resolve_java_analyzer};
use crate::analyzer::usages::model::{FuzzyResult, UsageHit};
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::UsageAnalyzer;
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile};
use crate::hash::HashSet;
use std::collections::BTreeSet;

#[derive(Default)]
pub struct JavaUsageGraphStrategy {
    _private: (),
}

impl JavaUsageGraphStrategy {
    pub fn new() -> Self {
        Self { _private: () }
    }

    pub fn can_handle(target: &CodeUnit) -> bool {
        language_for_target(target) == Language::Java
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
        if language_for_target(target) != Language::Java {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetLanguage("target is not Java"),
                "JavaUsageGraphStrategy",
            );
        }

        let Some(java) = resolve_java_analyzer(analyzer) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::MissingAnalyzerCapability(
                    "analyzer does not expose JavaAnalyzer",
                ),
                "JavaUsageGraphStrategy",
            );
        };

        let Some(spec) = TargetSpec::from_target(java, target) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetShape("target shape is unsupported"),
                "JavaUsageGraphStrategy",
            );
        };

        let files: HashSet<ProjectFile> = candidate_files
            .iter()
            .filter(|file| file.rel_path().extension().and_then(|ext| ext.to_str()) == Some("java"))
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
            scan_file(java, analyzer, &file, &spec, &mut state);
            if *state.limit_exceeded {
                break;
            }
        }

        if hits.is_empty() && saw_unproven_match {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsafeInference("no proven structured hits"),
                "JavaUsageGraphStrategy",
            );
        }

        if hits.is_empty() && raw_match_count > 0 {
            return GraphUsageOutcome::Resolved(FuzzyResult::success(
                target.clone(),
                BTreeSet::new(),
            ));
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

impl UsageAnalyzer for JavaUsageGraphStrategy {
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
