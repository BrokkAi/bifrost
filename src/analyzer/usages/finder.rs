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
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::php_graph::PhpUsageGraphStrategy;
use crate::analyzer::usages::python_graph::PythonExportUsageGraphStrategy;
use crate::analyzer::usages::rust_graph::RustExportUsageGraphStrategy;
use crate::analyzer::usages::scala_graph::ScalaUsageGraphStrategy;
use crate::analyzer::usages::traits::{CandidateFileProvider, GraphUsageAnalyzer};
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
    pub graph_failure: Option<crate::analyzer::usages::model::UsageAnalysisDiagnostic>,
}

/// Facade that wires a [`CandidateFileProvider`] together with language-specific usage
/// dispatch for a single fuzzy lookup. The strategy chosen depends on the target's language:
///
/// - JavaScript / TypeScript, Python, PHP, Rust, Java, C#, C++, Go, and Scala targets
///   are routed to their graph strategy first.
/// - Graph strategies can explicitly mark an internal outcome as fallback-safe; those
///   diagnostics are surfaced as failures instead of being masked by text matches.
/// - Targets without a graph strategy surface a structured unsupported-language failure.
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
                graph_failure: None,
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

        let mut graph_failure = None;
        let result = match graph_find_usages(
            language_for_target(target),
            analyzer,
            overloads,
            &candidates,
            max_usages,
        ) {
            GraphUsageOutcome::Resolved(result) => result,
            GraphUsageOutcome::FallbackSafe(diagnostic) => {
                graph_failure = Some(diagnostic.clone());
                FuzzyResult::Failure {
                    fq_name: diagnostic.fq_name,
                    reason: diagnostic.reason,
                }
            }
            GraphUsageOutcome::TerminalFailure(diagnostic) => {
                graph_failure = Some(diagnostic.clone());
                FuzzyResult::Failure {
                    fq_name: diagnostic.fq_name,
                    reason: diagnostic.reason,
                }
            }
        };

        QueryResult {
            candidate_files: candidates,
            candidate_files_truncated,
            result,
            graph_failure,
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

macro_rules! impl_graph_usage_analyzer {
    ($strategy:ty) => {
        impl GraphUsageAnalyzer for $strategy {
            fn find_graph_usages(
                &self,
                analyzer: &dyn IAnalyzer,
                overloads: &[CodeUnit],
                candidate_files: &HashSet<ProjectFile>,
                max_usages: usize,
            ) -> GraphUsageOutcome {
                <$strategy>::find_graph_usages(
                    self,
                    analyzer,
                    overloads,
                    candidate_files,
                    max_usages,
                )
            }
        }
    };
}

impl_graph_usage_analyzer!(JsTsExportUsageGraphStrategy);
impl_graph_usage_analyzer!(PythonExportUsageGraphStrategy);
impl_graph_usage_analyzer!(PhpUsageGraphStrategy);
impl_graph_usage_analyzer!(RustExportUsageGraphStrategy);
impl_graph_usage_analyzer!(JavaUsageGraphStrategy);
impl_graph_usage_analyzer!(CSharpUsageGraphStrategy);
impl_graph_usage_analyzer!(CppUsageGraphStrategy);
impl_graph_usage_analyzer!(GoUsageGraphStrategy);
impl_graph_usage_analyzer!(ScalaUsageGraphStrategy);

fn graph_strategy_find_usages(
    strategy: &dyn GraphUsageAnalyzer,
    analyzer: &dyn IAnalyzer,
    overloads: &[CodeUnit],
    candidates: &HashSet<ProjectFile>,
    max_usages: usize,
) -> GraphUsageOutcome {
    strategy.find_graph_usages(analyzer, overloads, candidates, max_usages)
}

fn graph_find_usages(
    language: Language,
    analyzer: &dyn IAnalyzer,
    overloads: &[CodeUnit],
    candidates: &HashSet<ProjectFile>,
    max_usages: usize,
) -> GraphUsageOutcome {
    match language {
        Language::JavaScript | Language::TypeScript => graph_strategy_find_usages(
            &JsTsExportUsageGraphStrategy::new(),
            analyzer,
            overloads,
            candidates,
            max_usages,
        ),
        Language::Python => graph_strategy_find_usages(
            &PythonExportUsageGraphStrategy::new(),
            analyzer,
            overloads,
            candidates,
            max_usages,
        ),
        Language::Php => graph_strategy_find_usages(
            &PhpUsageGraphStrategy::new(),
            analyzer,
            overloads,
            candidates,
            max_usages,
        ),
        Language::Rust => graph_strategy_find_usages(
            &RustExportUsageGraphStrategy::new(),
            analyzer,
            overloads,
            candidates,
            max_usages,
        ),
        Language::Java => graph_strategy_find_usages(
            &JavaUsageGraphStrategy::new(),
            analyzer,
            overloads,
            candidates,
            max_usages,
        ),
        Language::CSharp => graph_strategy_find_usages(
            &CSharpUsageGraphStrategy::new(),
            analyzer,
            overloads,
            candidates,
            max_usages,
        ),
        Language::Cpp => graph_strategy_find_usages(
            &CppUsageGraphStrategy::new(),
            analyzer,
            overloads,
            candidates,
            max_usages,
        ),
        Language::Go => graph_strategy_find_usages(
            &GoUsageGraphStrategy::new(),
            analyzer,
            overloads,
            candidates,
            max_usages,
        ),
        Language::Scala => graph_strategy_find_usages(
            &ScalaUsageGraphStrategy::new(),
            analyzer,
            overloads,
            candidates,
            max_usages,
        ),
        Language::None => GraphUsageOutcome::terminal_failure(
            overloads
                .first()
                .map(|target| target.fq_name().to_string())
                .unwrap_or_default(),
            GraphFailureReason::UnsupportedTargetLanguage("target language is unsupported"),
            "UsageFinder",
        ),
    }
}
