use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile};
use crate::hash::HashSet;
use crate::usages::candidates::{
    FallbackCandidateProvider, ImportGraphCandidateProvider, TextSearchCandidateProvider,
    default_provider,
};
use crate::usages::js_ts_graph::JsTsExportUsageGraphStrategy;
use crate::usages::model::FuzzyResult;
use crate::usages::regex_analyzer::RegexUsageAnalyzer;
use crate::usages::traits::{CandidateFileProvider, UsageAnalyzer};

/// Languages whose targets are routed through [`JsTsExportUsageGraphStrategy`] first,
/// with the regex analyzer as the fallback when the graph returns
/// [`FuzzyResult::Failure`].
fn is_graph_routed(language: Language) -> bool {
    matches!(language, Language::JavaScript | Language::TypeScript)
}

fn target_language(target: &CodeUnit) -> Language {
    target
        .source()
        .rel_path()
        .extension()
        .and_then(|ext| ext.to_str())
        .map(Language::from_extension)
        .unwrap_or(Language::None)
}

type DefaultCandidateProvider =
    FallbackCandidateProvider<ImportGraphCandidateProvider, TextSearchCandidateProvider>;

type FileFilter = Box<dyn Fn(&ProjectFile) -> bool + Send + Sync>;

pub const DEFAULT_MAX_FILES: usize = 1000;
pub const DEFAULT_MAX_USAGES: usize = 1000;

pub struct QueryResult {
    pub candidate_files: HashSet<ProjectFile>,
    pub candidate_files_truncated: bool,
    pub result: FuzzyResult,
}

/// Facade that wires a [`CandidateFileProvider`] and a [`UsageAnalyzer`] together for a
/// single fuzzy lookup. The strategy chosen depends on the target's language:
///
/// - JavaScript / TypeScript targets are routed to [`JsTsExportUsageGraphStrategy`]
///   (Phase 7), which falls through to the regex analyzer when it cannot infer a seed.
/// - Every other language falls through to [`RegexUsageAnalyzer`].
///
/// JDT-based Java analysis is intentionally omitted; bifrost is tree-sitter only.
pub struct UsageFinder {
    fallback_candidate_provider: DefaultCandidateProvider,
    fallback_usage_analyzer: Box<dyn UsageAnalyzer>,
    js_ts_graph_analyzer: Box<dyn UsageAnalyzer>,
    file_filter: Option<FileFilter>,
}

impl UsageFinder {
    pub fn new() -> Self {
        Self {
            fallback_candidate_provider: default_provider(),
            fallback_usage_analyzer: Box::new(RegexUsageAnalyzer::new()),
            js_ts_graph_analyzer: Box::new(JsTsExportUsageGraphStrategy::new()),
            file_filter: None,
        }
    }

    pub fn with_file_filter<F>(mut self, filter: F) -> Self
    where
        F: Fn(&ProjectFile) -> bool + Send + Sync + 'static,
    {
        self.file_filter = Some(Box::new(filter));
        self
    }

    pub fn query(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        max_files: usize,
        max_usages: usize,
    ) -> QueryResult {
        self.query_with_provider(analyzer, overloads, None, max_files, max_usages)
    }

    pub fn query_with_provider(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        explicit_provider: Option<&dyn CandidateFileProvider>,
        max_files: usize,
        max_usages: usize,
    ) -> QueryResult {
        if overloads.is_empty() {
            return QueryResult {
                candidate_files: HashSet::default(),
                candidate_files_truncated: false,
                result: FuzzyResult::empty_success(),
            };
        }

        let target = &overloads[0];
        let mut candidates: HashSet<ProjectFile> = match explicit_provider {
            Some(provider) => provider.find_candidates(target, analyzer),
            None => self
                .fallback_candidate_provider
                .find_candidates(target, analyzer),
        };

        if let Some(filter) = self.file_filter.as_ref() {
            candidates.retain(|file| filter(file));
        }

        let candidate_files_truncated = candidates.len() > max_files;
        if candidate_files_truncated {
            // HashSet has no insertion-order guarantee; the brokk Java code relies on
            // Java's HashSet iteration too, so we accept the same nondeterminism here.
            let kept: HashSet<ProjectFile> = candidates.into_iter().take(max_files).collect();
            candidates = kept;
        }

        let language = target_language(target);
        let result = if is_graph_routed(language) {
            // Try the graph strategy first; on Failure (no seed could be inferred) fall
            // back to the regex analyzer so callers still get best-effort results.
            match self.js_ts_graph_analyzer.find_usages(
                analyzer,
                overloads,
                &candidates,
                max_usages,
            ) {
                FuzzyResult::Failure { .. } => self.fallback_usage_analyzer.find_usages(
                    analyzer,
                    overloads,
                    &candidates,
                    max_usages,
                ),
                other => other,
            }
        } else {
            self.fallback_usage_analyzer
                .find_usages(analyzer, overloads, &candidates, max_usages)
        };

        QueryResult {
            candidate_files: candidates,
            candidate_files_truncated,
            result,
        }
    }

    pub fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        max_files: usize,
        max_usages: usize,
    ) -> FuzzyResult {
        self.query(analyzer, overloads, max_files, max_usages)
            .result
    }

    pub fn find_usages_default(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
    ) -> FuzzyResult {
        self.find_usages(analyzer, overloads, DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES)
    }
}

impl Default for UsageFinder {
    fn default() -> Self {
        Self::new()
    }
}
