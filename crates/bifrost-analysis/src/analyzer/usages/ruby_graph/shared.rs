use super::inverted;
use crate::analyzer::usages::common::analyzed_files_for_language;
use crate::analyzer::usages::inverted_edges::{UsageEdgeWeights, UsageEdges};
use crate::analyzer::usages::traits::UsageEdgeResolver;
use crate::analyzer::{IAnalyzer, Language, ProjectFile, RubyAnalyzer, resolve_analyzer};
use crate::hash::HashSet;

pub(crate) struct RubyEdgeResolver<'a> {
    ruby: &'a RubyAnalyzer,
    files: Vec<ProjectFile>,
}

impl<'a> UsageEdgeResolver<'a> for RubyEdgeResolver<'a> {
    fn try_new(analyzer: &'a dyn IAnalyzer) -> Option<Self> {
        let ruby = resolve_analyzer::<RubyAnalyzer>(analyzer)?;
        let files = analyzed_files_for_language(analyzer, Language::Ruby);
        if files.is_empty() {
            return None;
        }
        Some(Self { ruby, files })
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
        inverted::build_ruby_edges(analyzer, self.ruby, &self.files, nodes, keep_file)
    }

    fn build_edge_weights<F>(
        &self,
        analyzer: &dyn IAnalyzer,
        nodes: &HashSet<String>,
        keep_file: F,
    ) -> UsageEdgeWeights
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        inverted::build_ruby_edges(analyzer, self.ruby, &self.files, nodes, keep_file)
    }
}
