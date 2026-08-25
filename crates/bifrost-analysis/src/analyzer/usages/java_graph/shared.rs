use super::{build_java_edges, scan_java_file_replayable};
use crate::analyzer::usages::common::language_for_file;
use crate::analyzer::usages::inverted_edges::EdgeNodeDomain;
use crate::analyzer::usages::inverted_edges::{UsageEdgeWeights, UsageEdges};
use crate::analyzer::usages::model::{FuzzyResult, UsageHit};
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::{UsageQueryResolver, UsageScanScope};
use crate::analyzer::{AnalyzerQueryScope, QueryScope};
use crate::analyzer::{
    BulkFileStateSource, CodeUnit, IAnalyzer, JavaAnalyzer, Language, ProjectFile, resolve_analyzer,
};
use crate::hash::HashSet;
use brokk_bifrost_jvm::java::graph::extractor::ScanState;
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
        let scope = AnalyzerQueryScope::new(analyzer);
        let token = scope.token();
        let Some(target) = overloads.first() else {
            return GraphUsageOutcome::Resolved(FuzzyResult::empty_success());
        };
        let uncancelled = crate::CancellationToken::new();
        let cancellation = scan_scope.cancellation().unwrap_or(&uncancelled);
        let relational_session =
            crate::analyzer::relational_frontier::RelationalFrontierSession::new(
                analyzer,
                cancellation,
            );
        let target_spec_scope = crate::profiling::scope("java_graph::target_spec");
        let Some(spec) = brokk_bifrost_jvm::java::graph::resolver::TargetSpec::from_targets(
            self.java, overloads,
        ) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetShape("target shape is unsupported"),
                "JavaUsageGraphStrategy",
            );
        };
        drop(target_spec_scope);

        let select_files_scope = crate::profiling::scope("java_graph::select_files");
        let candidate_files = scan_scope.candidate_files();
        let mut files: HashSet<ProjectFile> = candidate_files
            .iter()
            .filter(|file| language_for_file(file) == Language::Java)
            .cloned()
            .collect();
        if scan_scope.allows(target.source()) {
            files.insert(target.source().clone());
        }
        drop(select_files_scope);
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
        for file in &files {
            let _scan_scope = crate::profiling::scope("java_graph::scan_file");
            match scan_java_file_replayable(
                &relational_session,
                analyzer,
                self.java,
                token,
                file,
                &spec,
                &mut state,
            ) {
                crate::analyzer::RelationalFrontierOutcome::Complete(()) => {}
                crate::analyzer::RelationalFrontierOutcome::Cancelled => break,
                crate::analyzer::RelationalFrontierOutcome::Failed(error) => {
                    crate::profiling::note_with(|| {
                        format!("Java file frontier failed: {}", error.message())
                    });
                    return GraphUsageOutcome::fallback_safe(
                        target.fq_name(),
                        GraphFailureReason::UnsupportedTargetShape("a Java file frontier failed"),
                        "JavaUsageGraphStrategy",
                    );
                }
            }
            if *state.limit_exceeded {
                break;
            }
        }
        let _scala_scope = crate::profiling::scope("java_graph::scan_scala_files");
        super::scan_scala_files_for_java_target(analyzer, candidate_files, &spec, &mut state, None);
        drop(_scala_scope);
        // A Java class is equally nameable from Kotlin source; the realm is one
        // candidate space, so find-references on a Java type must see its Kotlin
        // call sites too (#1239 milestone 4).
        let _kotlin_scope = crate::profiling::scope("java_graph::scan_kotlin_files");
        crate::analyzer::usages::kotlin_graph::scan_kotlin_files_for_jvm_type(
            analyzer,
            candidate_files,
            target,
            max_usages,
            state.hits,
            state.unproven_hits,
            state.raw_match_count,
            state.limit_exceeded,
        );
        drop(_kotlin_scope);

        let external_callsites = crate::analyzer::usages::common::external_usage_hit_count(&hits);
        if limit_exceeded || external_callsites > max_usages {
            return GraphUsageOutcome::Resolved(FuzzyResult::TooManyCallsites {
                short_name: target.short_name().to_string(),
                total_callsites: external_callsites,
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

/// The whole-workspace `caller -> callee` scan behind this language's
/// [`LanguageEdgePass`](crate::analyzer::languages::LanguageEdgePass): borrow the concrete
/// analyzer once, then walk every file once and finalize into either site-bearing edges or
/// reference-kind weights.
impl<'a> JavaEdgeResolver<'a> {
    pub(crate) fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        let java = resolve_analyzer::<JavaAnalyzer>(analyzer)?;
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
        let selected_files: Vec<_> = self
            .files
            .iter()
            .filter(|file| keep_file(file))
            .cloned()
            .collect();
        let file_states = self
            .java
            .bulk_file_states(selected_files, BulkFileStateSource::Omit);
        build_java_edges(
            analyzer,
            self.java,
            &self.files,
            &file_states,
            EdgeNodeDomain::Closed(nodes),
            keep_file,
        )
    }

    pub(crate) fn build_rooted_edges<F>(
        &self,
        analyzer: &dyn IAnalyzer,
        callers: &HashSet<String>,
        keep_file: F,
    ) -> UsageEdges
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        let selected_files: Vec<_> = self
            .files
            .iter()
            .filter(|file| keep_file(file))
            .cloned()
            .collect();
        let file_states = self
            .java
            .bulk_file_states(selected_files, BulkFileStateSource::Omit);
        build_java_edges(
            analyzer,
            self.java,
            &self.files,
            &file_states,
            EdgeNodeDomain::Rooted(callers),
            keep_file,
        )
    }

    pub(crate) fn build_edge_weights<F>(
        &self,
        analyzer: &dyn IAnalyzer,
        nodes: &HashSet<String>,
        keep_file: F,
    ) -> UsageEdgeWeights
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        let selected_files: Vec<_> = self
            .files
            .iter()
            .filter(|file| keep_file(file))
            .cloned()
            .collect();
        let file_states = self
            .java
            .bulk_file_states(selected_files, BulkFileStateSource::Omit);
        build_java_edges(
            analyzer,
            self.java,
            &self.files,
            &file_states,
            EdgeNodeDomain::Closed(nodes),
            keep_file,
        )
    }
}
