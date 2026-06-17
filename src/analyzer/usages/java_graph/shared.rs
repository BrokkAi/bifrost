use super::extractor::{ScanState, scan_file};
use super::inverted::{self, ParsedJavaFile};
use super::jvm_scala::scan_scala_files_for_java_type;
use super::resolver::{TargetSpec, resolve_java_analyzer};
use crate::analyzer::usages::common::language_for_file;
use crate::analyzer::usages::inverted_edges::UsageEdges;
use crate::analyzer::usages::model::{FuzzyResult, UsageHit};
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::{CodeUnit, IAnalyzer, JavaAnalyzer, Language, ProjectFile};
use crate::hash::{HashMap, HashSet, map_with_capacity};
use crate::text_utils::compute_line_starts;
use rayon::prelude::*;
use std::collections::BTreeSet;
use tree_sitter::Parser;

pub(super) struct JavaEdgeGraph {
    pub(super) files: Vec<ProjectFile>,
    pub(super) parsed: HashMap<ProjectFile, ParsedJavaFile>,
}

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
    graph: JavaEdgeGraph,
}

impl<'a> JavaEdgeResolver<'a> {
    pub(crate) fn new<F>(analyzer: &'a dyn IAnalyzer, keep_file: &F) -> Option<Self>
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        let java = resolve_java_analyzer(analyzer)?;
        let files: Vec<ProjectFile> = analyzer
            .project()
            .analyzable_files(Language::Java)
            .ok()?
            .into_iter()
            .collect();
        let parsed_files: Vec<(ProjectFile, ParsedJavaFile)> = files
            .par_iter()
            .filter(|file| keep_file(file))
            .filter_map(parse_java_file)
            .collect();
        let mut parsed: HashMap<ProjectFile, ParsedJavaFile> =
            map_with_capacity(parsed_files.len());
        for (file, parsed_file) in parsed_files {
            parsed.insert(file, parsed_file);
        }

        Some(Self {
            java,
            graph: JavaEdgeGraph { files, parsed },
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
        inverted::build_java_edges(analyzer, self.java, &self.graph, nodes, keep_file)
    }
}

fn parse_java_file(file: &ProjectFile) -> Option<(ProjectFile, ParsedJavaFile)> {
    let source = file.read_to_string().ok()?;
    if source.is_empty() {
        return None;
    }
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .ok()?;
    let tree = parser.parse(source.as_str(), None)?;
    let line_starts = compute_line_starts(&source);
    Some((
        file.clone(),
        ParsedJavaFile {
            source,
            tree,
            line_starts,
        },
    ))
}
