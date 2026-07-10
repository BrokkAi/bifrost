use super::extractor::scan_file;
use super::inverted::{self, ProjectTypes};
use super::resolver::TargetSpec;
use crate::analyzer::usages::common::{analyzed_files_for_language, language_for_file};
use crate::analyzer::usages::inverted_edges::UsageEdges;
use crate::analyzer::usages::model::{FuzzyResult, UsageHit};
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::{UsageEdgeResolver, UsageQueryResolver, UsageScanScope};
use crate::analyzer::{
    CodeUnit, IAnalyzer, Language, ProjectFile, ScalaAnalyzer, resolve_analyzer,
};
use crate::hash::HashSet;
use std::collections::BTreeSet;
use std::sync::Arc;

pub(super) struct ScalaEdgeGraph<'a> {
    pub(super) scala: &'a ScalaAnalyzer,
    pub(super) files: Vec<ProjectFile>,
    pub(super) types: Arc<ProjectTypes>,
}

pub(crate) struct ScalaQueryResolver<'a> {
    scala: &'a ScalaAnalyzer,
}

impl<'a> UsageQueryResolver<'a> for ScalaQueryResolver<'a> {
    fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        Some(Self {
            scala: resolve_analyzer::<ScalaAnalyzer>(analyzer)?,
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
        let Some(spec) = TargetSpec::from_target(self.scala, target) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetShape("target shape is unsupported"),
                "ScalaUsageGraphStrategy",
            );
        };

        let candidate_files = scan_scope.candidate_files();
        let mut files: HashSet<ProjectFile> = candidate_files
            .iter()
            .filter(|file| language_for_file(file) == Language::Scala)
            .cloned()
            .collect();
        if scan_scope.allows(target.source()) {
            files.insert(target.source().clone());
        }

        let mut hits: BTreeSet<UsageHit> = BTreeSet::new();
        let mut limit_exceeded = false;
        for file in files {
            if scan_scope.is_cancelled() {
                break;
            }
            scan_file(
                self.scala,
                analyzer,
                &file,
                &spec,
                &mut hits,
                max_usages,
                &mut limit_exceeded,
            );
            if hits.len() > max_usages {
                return GraphUsageOutcome::Resolved(FuzzyResult::TooManyCallsites {
                    short_name: target.short_name().to_string(),
                    total_callsites: hits.len(),
                    limit: max_usages,
                    sample_hits: hits,
                });
            }
            if limit_exceeded {
                break;
            }
        }

        GraphUsageOutcome::Resolved(FuzzyResult::success(target.clone(), hits))
    }
}

pub(crate) struct ScalaEdgeResolver<'a> {
    graph: ScalaEdgeGraph<'a>,
}

impl<'a> UsageEdgeResolver<'a> for ScalaEdgeResolver<'a> {
    fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        let scala = resolve_analyzer::<ScalaAnalyzer>(analyzer)?;
        let files = analyzed_files_for_language(analyzer, Language::Scala);
        let types = scala.project_types();

        Some(Self {
            graph: ScalaEdgeGraph {
                scala,
                files,
                types,
            },
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
        inverted::build_scala_edges(analyzer, &self.graph, nodes, keep_file)
    }
}
