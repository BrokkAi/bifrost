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
use crate::analyzer::usages::ruby_graph::RubyUsageGraphStrategy;
use crate::analyzer::usages::rust_graph::RustExportUsageGraphStrategy;
use crate::analyzer::usages::scala_graph::ScalaUsageGraphStrategy;
use crate::analyzer::usages::traits::{CandidateFileProvider, GraphUsageAnalyzer};
use crate::analyzer::{CodeUnit, IAnalyzer, Language, PhpAnalyzer, ProjectFile, resolve_analyzer};
use crate::hash::HashSet;
use std::collections::BTreeSet;

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
        let mut protected_candidates = candidates.clone();

        if explicit_provider.is_none() {
            add_php_composer_candidates(target, analyzer, &mut candidates);
            add_php_import_alias_candidates(target, analyzer, &mut candidates);
        }

        if let Some(filter) = self.file_filter.as_ref() {
            candidates.retain(|file| filter(file));
            protected_candidates.retain(|file| filter(file));
        }

        let candidate_files_truncated = candidates.len() > max_files;
        if candidate_files_truncated {
            candidates = truncate_candidates(candidates, &protected_candidates, max_files);
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

fn add_php_composer_candidates(
    target: &CodeUnit,
    analyzer: &dyn IAnalyzer,
    candidates: &mut HashSet<ProjectFile>,
) {
    if language_for_target(target) != Language::Php {
        return;
    }
    let Some(php) = resolve_analyzer::<PhpAnalyzer>(analyzer) else {
        return;
    };
    if !php.target_has_composer_autoload_visibility(target) {
        return;
    }
    let Ok(files) = analyzer.project().analyzable_files(Language::Php) else {
        return;
    };
    candidates.extend(files);
}

fn add_php_import_alias_candidates(
    target: &CodeUnit,
    analyzer: &dyn IAnalyzer,
    candidates: &mut HashSet<ProjectFile>,
) {
    if language_for_target(target) != Language::Php {
        return;
    }
    let Some(php) = resolve_analyzer::<PhpAnalyzer>(analyzer) else {
        return;
    };
    let relevant_types = php_relevant_candidate_types(target, analyzer, php);
    if relevant_types.is_empty() {
        return;
    }
    for fq_name in &relevant_types {
        candidates.extend(
            analyzer
                .definitions(fq_name)
                .filter(|unit| unit.is_class())
                .map(|unit| unit.source().clone()),
        );
    }
    let Ok(files) = analyzer.project().analyzable_files(Language::Php) else {
        return;
    };
    for file in files {
        let aliases = php.use_aliases_by_kind_of(&file);
        if aliases
            .type_aliases
            .values()
            .any(|fq_name| relevant_types.contains(fq_name))
        {
            candidates.insert(file);
        }
    }
}

fn php_relevant_candidate_types(
    target: &CodeUnit,
    analyzer: &dyn IAnalyzer,
    php: &PhpAnalyzer,
) -> HashSet<String> {
    let mut types = HashSet::default();
    let owner = if target.is_class() {
        Some(target.clone())
    } else {
        php.parent_of(target)
    };
    let Some(owner) = owner else {
        return types;
    };
    types.insert(owner.fq_name());
    if let Some(provider) = analyzer.type_hierarchy_provider() {
        types.extend(
            provider
                .get_descendants(&owner)
                .into_iter()
                .map(|unit| unit.fq_name()),
        );
    }
    types
}

fn truncate_candidates(
    candidates: HashSet<ProjectFile>,
    protected_candidates: &HashSet<ProjectFile>,
    max_files: usize,
) -> HashSet<ProjectFile> {
    if max_files == 0 {
        return HashSet::default();
    }

    let mut kept = HashSet::default();
    for file in sorted_files(protected_candidates)
        .into_iter()
        .take(max_files)
    {
        kept.insert(file);
    }

    if kept.len() >= max_files {
        return kept;
    }

    for file in sorted_files(&candidates) {
        if kept.len() >= max_files {
            break;
        }
        kept.insert(file);
    }
    kept
}

fn sorted_files(files: &HashSet<ProjectFile>) -> Vec<ProjectFile> {
    files
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
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
impl_graph_usage_analyzer!(RubyUsageGraphStrategy);

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
        Language::Ruby => graph_strategy_find_usages(
            &RubyUsageGraphStrategy::new(),
            analyzer,
            overloads,
            candidates,
            max_usages,
        ),
        Language::None => GraphUsageOutcome::terminal_failure(
            overloads[0].fq_name(),
            GraphFailureReason::UnsupportedTargetLanguage(
                "no graph usage strategy is available for this target language",
            ),
            "UsageFinder",
        ),
    }
}
