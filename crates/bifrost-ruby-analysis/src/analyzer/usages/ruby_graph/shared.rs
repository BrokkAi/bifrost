use crate::analyzer::usages::ruby_graph::build_ruby_edges;

use crate::analyzer::usages::ruby_graph::with_ruby_graph_source;

use brokk_bifrost_analysis::analyzer::usages::common::analyzed_files_for_language;

use brokk_bifrost_analysis::analyzer::usages::inverted_edges::EdgeNodeDomain;

use brokk_bifrost_core::analyzer::usages::inverted_edges::UsageEdges;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use crate::analyzer::RubyAnalyzer;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

use brokk_bifrost_core::hash::HashSet;

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
        if files.is_empty() || !ruby.canonical_sources_ready() {
            return None;
        }
        Some(Self { ruby, files })
    }

    pub(crate) fn build_edges<Output, F>(
        &self,
        analyzer: &dyn IAnalyzer,
        nodes: &HashSet<String>,
        keep_file: F,
    ) -> Option<Output>
    where
        Output:
            brokk_bifrost_analysis::analyzer::usages::inverted_edges::UsageEdgeBuildOutput<String>,
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        with_ruby_graph_source(analyzer, |graph| {
            build_ruby_edges(
                graph,
                analyzer,
                self.ruby,
                &self.files,
                EdgeNodeDomain::Closed(nodes),
                keep_file,
            )
        })
    }

    pub(crate) fn build_rooted_edges<F>(
        &self,
        analyzer: &dyn IAnalyzer,
        callers: &HashSet<String>,
        keep_file: F,
    ) -> Option<UsageEdges>
    where
        F: Fn(&ProjectFile) -> bool + Sync,
    {
        with_ruby_graph_source(analyzer, |graph| {
            build_ruby_edges(
                graph,
                analyzer,
                self.ruby,
                &self.files,
                EdgeNodeDomain::Rooted(callers),
                keep_file,
            )
        })
    }
}
