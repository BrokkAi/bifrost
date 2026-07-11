use super::extractor::scan_file;
use super::inverted::{self, ProjectTypes};
use super::resolver::TargetSpec;
use crate::analyzer::tree_sitter_analyzer::FileState;
use crate::analyzer::usages::common::language_for_file;
use crate::analyzer::usages::inverted_edges::UsageEdges;
use crate::analyzer::usages::model::{FuzzyResult, UsageHit};
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::{UsageEdgeResolver, UsageQueryResolver, UsageScanScope};
use crate::analyzer::{
    BulkFileStateSource, CodeUnit, IAnalyzer, ImportInfo, Language, ProjectFile, ScalaAnalyzer,
    resolve_analyzer,
};
use crate::hash::HashMap;
use crate::hash::HashSet;
use std::collections::BTreeSet;

pub(super) struct ScalaEdgeGraph {
    pub(super) files: Vec<ProjectFile>,
    pub(super) types: ProjectTypes,
    pub(super) package_by_file: HashMap<ProjectFile, String>,
    pub(super) imports_by_file: HashMap<ProjectFile, Vec<ImportInfo>>,
    pub(super) file_states: HashMap<ProjectFile, FileState>,
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
    scala: &'a ScalaAnalyzer,
    graph: ScalaEdgeGraph,
}

impl<'a> UsageEdgeResolver<'a> for ScalaEdgeResolver<'a> {
    fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        let scala = resolve_analyzer::<ScalaAnalyzer>(analyzer)?;
        let files: Vec<ProjectFile> = analyzer
            .project()
            .analyzable_files(Language::Scala)
            .ok()?
            .into_iter()
            .collect();
        let file_states = scala.bulk_file_states(files.clone(), BulkFileStateSource::Omit);
        let types = ProjectTypes::build_from_file_states(scala, &file_states);

        Some(Self {
            scala,
            graph: ScalaEdgeGraph {
                files,
                types,
                package_by_file: self::package_by_file(&file_states),
                imports_by_file: file_states
                    .iter()
                    .map(|(file, state)| (file.clone(), state.imports.clone()))
                    .collect(),
                file_states,
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
        inverted::build_scala_edges(analyzer, self.scala, &self.graph, nodes, keep_file)
    }
}

fn package_by_file(states: &HashMap<ProjectFile, FileState>) -> HashMap<ProjectFile, String> {
    states
        .iter()
        .map(|(file, state)| (file.clone(), state.package_name.clone()))
        .collect()
}
