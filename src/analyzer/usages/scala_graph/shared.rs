use super::extractor::scan_file;
use super::inverted::{self, ParsedScalaFile, ProjectTypes};
use super::resolver::{TargetSpec, resolve_scala_analyzer};
use crate::analyzer::usages::common::language_for_file;
use crate::analyzer::usages::inverted_edges::UsageEdges;
use crate::analyzer::usages::model::{FuzzyResult, UsageHit};
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::parsed_tree::parse_kept_tree_sitter_files;
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile, ScalaAnalyzer};
use crate::hash::{HashMap, HashSet};
use std::collections::BTreeSet;

pub(super) struct ScalaEdgeGraph<'a> {
    pub(super) scala: &'a ScalaAnalyzer,
    pub(super) files: Vec<ProjectFile>,
    pub(super) types: ProjectTypes,
    pub(super) parsed: HashMap<ProjectFile, ParsedScalaFile>,
}

pub(crate) struct ScalaQueryResolver<'a> {
    scala: &'a ScalaAnalyzer,
}

impl<'a> ScalaQueryResolver<'a> {
    pub(crate) fn new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        Some(Self {
            scala: resolve_scala_analyzer(analyzer)?,
        })
    }

    pub(crate) fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        target: &CodeUnit,
        candidate_files: &HashSet<ProjectFile>,
        max_usages: usize,
    ) -> GraphUsageOutcome {
        let Some(spec) = TargetSpec::from_target(self.scala, target) else {
            return GraphUsageOutcome::fallback_safe(
                target.fq_name(),
                GraphFailureReason::UnsupportedTargetShape("target shape is unsupported"),
                "ScalaUsageGraphStrategy",
            );
        };

        let files: HashSet<ProjectFile> = candidate_files
            .iter()
            .filter(|file| language_for_file(file) == Language::Scala)
            .cloned()
            .chain(std::iter::once(target.source().clone()))
            .collect();

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

impl<'a> ScalaEdgeResolver<'a> {
    pub(crate) fn new<F>(analyzer: &'a dyn IAnalyzer, keep_file: &F) -> Option<Self>
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        let scala = resolve_scala_analyzer(analyzer)?;
        let files: Vec<ProjectFile> = analyzer
            .project()
            .analyzable_files(Language::Scala)
            .ok()?
            .into_iter()
            .collect();
        let types = ProjectTypes::build(scala);
        let language = tree_sitter_scala::LANGUAGE.into();
        let parsed = parse_kept_tree_sitter_files(&files, keep_file, &language);

        Some(Self {
            graph: ScalaEdgeGraph {
                scala,
                files,
                types,
                parsed,
            },
        })
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
        inverted::build_scala_edges(analyzer, &self.graph, nodes, keep_file)
    }
}
