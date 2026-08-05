use super::{build_ruby_edges, with_ruby_graph_source};
use crate::analyzer::usages::common::analyzed_files_for_language;
use crate::analyzer::usages::inverted_edges::{UsageEdgeWeights, UsageEdges};
use crate::analyzer::{IAnalyzer, Language, ProjectFile, RubyAnalyzer, resolve_analyzer};
use crate::hash::HashSet;

pub(crate) struct RubyEdgeResolver<'a> {
    ruby: &'a RubyAnalyzer,
    files: Vec<ProjectFile>,
}

/// The whole-workspace `caller -> callee` scan behind this language's
/// [`LanguageEdgePass`](crate::analyzer::languages::LanguageEdgePass): borrow the concrete
/// analyzer once, then walk every file once and finalize into either site-bearing edges or
/// reference-kind weights.
impl<'a> RubyEdgeResolver<'a> {
    pub(crate) fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        let ruby = resolve_analyzer::<RubyAnalyzer>(analyzer)?;
        let files = analyzed_files_for_language(analyzer, Language::Ruby);
        if files.is_empty() {
            return None;
        }
        Some(Self { ruby, files })
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
        with_ruby_graph_source(analyzer, |graph| {
            build_ruby_edges(graph, analyzer, self.ruby, &self.files, nodes, keep_file)
        })
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
        with_ruby_graph_source(analyzer, |graph| {
            build_ruby_edges(graph, analyzer, self.ruby, &self.files, nodes, keep_file)
        })
    }
}
