use crate::analyzer::usages::candidates::{
    FallbackCandidateProvider, ImportGraphCandidateProvider, TextSearchCandidateProvider,
    default_provider,
};
use crate::analyzer::usages::common::language_for_target;
use crate::analyzer::usages::cpp_graph::CppUsageGraphStrategy;
use crate::analyzer::usages::csharp_graph::CSharpUsageGraphStrategy;
use crate::analyzer::usages::go_graph::GoUsageGraphStrategy;
use crate::analyzer::usages::java_graph::JavaUsageGraphStrategy;
use crate::analyzer::usages::js_ts_graph::JsTsExportUsageGraphStrategy;
use crate::analyzer::usages::model::FuzzyResult;
use crate::analyzer::usages::php_graph::PhpUsageGraphStrategy;
use crate::analyzer::usages::python_graph::PythonExportUsageGraphStrategy;
use crate::analyzer::usages::regex_analyzer::RegexUsageAnalyzer;
use crate::analyzer::usages::rust_graph::RustExportUsageGraphStrategy;
use crate::analyzer::usages::scala_graph::ScalaUsageGraphStrategy;
use crate::analyzer::usages::traits::{CandidateFileProvider, UsageAnalyzer};
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile};
use crate::hash::HashSet;

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

/// Facade that wires a [`CandidateFileProvider`] together with language-specific usage
/// dispatch for a single fuzzy lookup. The strategy chosen depends on the target's language:
///
/// - JavaScript / TypeScript, Python, PHP, Rust, Java, C#, C++, Go, and Scala targets
///   are routed to their graph strategy first.
/// - Graph strategy failures fall through to [`RegexUsageAnalyzer`] so callers still get
///   best-effort results.
/// - Languages without a graph strategy go directly to [`RegexUsageAnalyzer`].
///
/// JDT-based Java analysis is intentionally omitted; bifrost is tree-sitter only.
pub struct UsageFinder {
    fallback_candidate_provider: DefaultCandidateProvider,
    file_filter: Option<FileFilter>,
}

impl UsageFinder {
    pub fn new() -> Self {
        Self {
            fallback_candidate_provider: default_provider(),
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

        let result = match graph_find_usages(
            language_for_target(target),
            analyzer,
            overloads,
            &candidates,
            max_usages,
        ) {
            // Try the graph strategy first; on Failure (no seed could be inferred) fall
            // back to the regex analyzer so callers still get best-effort results.
            Some(FuzzyResult::Failure { .. }) | None => {
                regex_find_usages(analyzer, overloads, &candidates, max_usages)
            }
            Some(other) => other,
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

fn graph_find_usages(
    language: Language,
    analyzer: &dyn IAnalyzer,
    overloads: &[CodeUnit],
    candidates: &HashSet<ProjectFile>,
    max_usages: usize,
) -> Option<FuzzyResult> {
    match language {
        Language::JavaScript | Language::TypeScript => Some(
            JsTsExportUsageGraphStrategy::new()
                .find_usages(analyzer, overloads, candidates, max_usages),
        ),
        Language::Python => Some(
            PythonExportUsageGraphStrategy::new()
                .find_usages(analyzer, overloads, candidates, max_usages),
        ),
        Language::Php => Some(
            PhpUsageGraphStrategy::new().find_usages(analyzer, overloads, candidates, max_usages),
        ),
        Language::Rust => Some(
            RustExportUsageGraphStrategy::new()
                .find_usages(analyzer, overloads, candidates, max_usages),
        ),
        Language::Java => Some(
            JavaUsageGraphStrategy::new().find_usages(analyzer, overloads, candidates, max_usages),
        ),
        Language::CSharp => Some(
            CSharpUsageGraphStrategy::new()
                .find_usages(analyzer, overloads, candidates, max_usages),
        ),
        Language::Cpp => Some(
            CppUsageGraphStrategy::new().find_usages(analyzer, overloads, candidates, max_usages),
        ),
        Language::Go => Some(
            GoUsageGraphStrategy::new().find_usages(analyzer, overloads, candidates, max_usages),
        ),
        Language::Scala => Some(
            ScalaUsageGraphStrategy::new().find_usages(analyzer, overloads, candidates, max_usages),
        ),
        _ => None,
    }
}

fn regex_find_usages(
    analyzer: &dyn IAnalyzer,
    overloads: &[CodeUnit],
    candidates: &HashSet<ProjectFile>,
    max_usages: usize,
) -> FuzzyResult {
    RegexUsageAnalyzer::new().find_usages(analyzer, overloads, candidates, max_usages)
}
