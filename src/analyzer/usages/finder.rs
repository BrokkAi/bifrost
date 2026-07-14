use crate::analyzer::usages::candidates::find_default_candidates_with_cancellation;
use crate::analyzer::usages::common::{analyzed_files_for_language, language_for_target};
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
use crate::analyzer::usages::traits::{CandidateFileProvider, GraphUsageAnalyzer, UsageScanScope};
use crate::analyzer::{
    AnalyzerQueryScope, CodeUnit, IAnalyzer, Language, PhpAnalyzer, ProjectFile, resolve_analyzer,
};
use crate::cancellation::CancellationToken;
use crate::hash::HashSet;
use std::collections::BTreeSet;

type FileFilter = Box<dyn Fn(&ProjectFile) -> bool + Send + Sync>;

pub const DEFAULT_MAX_FILES: usize = 1000;
pub const DEFAULT_MAX_USAGES: usize = 1000;

pub struct QueryResult {
    pub candidate_files: HashSet<ProjectFile>,
    pub candidate_files_truncated: bool,
    pub candidate_files_sample: Option<CandidateFilesSample>,
    pub result: FuzzyResult,
    pub graph_failure: Option<crate::analyzer::usages::model::UsageAnalysisDiagnostic>,
}

pub struct CandidateFilesSample {
    pub scanned: Vec<ProjectFile>,
    pub omitted: Vec<ProjectFile>,
    pub omitted_count: usize,
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
    file_filter: Option<FileFilter>,
    authoritative_scope: bool,
    cancellation: CancellationToken,
}

impl UsageFinder {
    pub fn new() -> Self {
        let cancellation = CancellationToken::default();
        Self {
            file_filter: None,
            authoritative_scope: false,
            cancellation,
        }
    }

    pub(crate) fn with_cancellation(mut self, cancellation: CancellationToken) -> Self {
        self.cancellation = cancellation;
        self
    }

    pub fn with_file_filter<F>(mut self, filter: F) -> Self
    where
        F: Fn(&ProjectFile) -> bool + Send + Sync + 'static,
    {
        self.file_filter = Some(Box::new(filter));
        self
    }

    pub fn with_authoritative_scope(mut self, authoritative: bool) -> Self {
        self.authoritative_scope = authoritative;
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
        let _scope = crate::profiling::scope("usages::UsageFinder::query_with_provider");
        let _query_scope = AnalyzerQueryScope::new(analyzer);
        if overloads.is_empty() || self.cancellation.is_cancelled() {
            return QueryResult {
                candidate_files: HashSet::default(),
                candidate_files_truncated: false,
                candidate_files_sample: None,
                result: FuzzyResult::empty_success(),
                graph_failure: None,
            };
        }

        let target = &overloads[0];
        let mut candidates: HashSet<ProjectFile> = {
            let _scope = crate::profiling::scope("usages::UsageFinder::candidate_discovery");
            match explicit_provider {
                Some(provider) => provider.find_candidates(target, analyzer),
                None => {
                    find_default_candidates_with_cancellation(target, analyzer, &self.cancellation)
                }
            }
        };
        if self.cancellation.is_cancelled() {
            return cancelled_query_result();
        }
        let mut protected_candidates = candidates.clone();

        if explicit_provider.is_none() {
            {
                let _scope =
                    crate::profiling::scope("usages::UsageFinder::php_composer_candidates");
                add_php_composer_candidates(target, analyzer, &mut candidates);
            }
            if self.cancellation.is_cancelled() {
                return cancelled_query_result();
            }
            {
                let _scope = crate::profiling::scope("usages::UsageFinder::php_alias_candidates");
                add_php_import_alias_candidates(target, analyzer, &mut candidates);
            }
        }

        if let Some(filter) = self.file_filter.as_ref() {
            candidates.retain(|file| !self.cancellation.is_cancelled() && filter(file));
            protected_candidates.retain(|file| !self.cancellation.is_cancelled() && filter(file));
        }
        if self.cancellation.is_cancelled() {
            return cancelled_query_result();
        }

        let candidate_files_truncated = candidates.len() > max_files;
        let all_candidates = candidate_files_truncated.then(|| candidates.clone());
        if candidate_files_truncated {
            candidates = truncate_candidates(candidates, &protected_candidates, max_files);
        }
        let candidate_files_sample = all_candidates
            .as_ref()
            .map(|all_candidates| candidate_files_sample(all_candidates, &candidates));

        let mut graph_failure = None;
        let scan_scope = UsageScanScope::with_cancellation(
            &candidates,
            self.authoritative_scope,
            &self.cancellation,
        );
        let result = match {
            let _scope = crate::profiling::scope("usages::UsageFinder::graph_find_usages");
            graph_find_usages(
                language_for_target(target),
                analyzer,
                overloads,
                &scan_scope,
                max_usages,
            )
        } {
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
        if self.cancellation.is_cancelled() {
            return cancelled_query_result();
        }

        QueryResult {
            candidate_files: candidates,
            candidate_files_truncated,
            candidate_files_sample,
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

fn cancelled_query_result() -> QueryResult {
    QueryResult {
        candidate_files: HashSet::default(),
        candidate_files_truncated: false,
        candidate_files_sample: None,
        result: FuzzyResult::empty_success(),
        graph_failure: None,
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
    candidates.extend(analyzed_files_for_language(analyzer, Language::Php));
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
    for file in analyzed_files_for_language(analyzer, Language::Php) {
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

const CANDIDATE_FILE_SAMPLE_LIMIT: usize = 10;

fn candidate_files_sample(
    all_candidates: &HashSet<ProjectFile>,
    scanned_candidates: &HashSet<ProjectFile>,
) -> CandidateFilesSample {
    let scanned = sorted_files(scanned_candidates)
        .into_iter()
        .take(CANDIDATE_FILE_SAMPLE_LIMIT)
        .collect();
    let omitted_all: HashSet<ProjectFile> = all_candidates
        .iter()
        .filter(|file| !scanned_candidates.contains(*file))
        .cloned()
        .collect();
    let omitted_count = omitted_all.len();
    let omitted = sorted_files(&omitted_all)
        .into_iter()
        .take(CANDIDATE_FILE_SAMPLE_LIMIT)
        .collect();
    CandidateFilesSample {
        scanned,
        omitted,
        omitted_count,
    }
}

fn sorted_files(files: &HashSet<ProjectFile>) -> Vec<ProjectFile> {
    files
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{CodeUnitType, EmptyAnalyzer, FileSetProject, Project, ProjectFile};
    use std::path::PathBuf;
    use std::sync::Arc;

    struct PanicCandidateProvider;

    impl CandidateFileProvider for PanicCandidateProvider {
        fn find_candidates(
            &self,
            _target: &CodeUnit,
            _analyzer: &dyn IAnalyzer,
        ) -> HashSet<ProjectFile> {
            panic!("pre-cancelled query must not discover candidates");
        }
    }

    #[test]
    fn pre_cancelled_query_skips_candidate_discovery() {
        let root = std::env::temp_dir();
        let project: Arc<dyn Project> = Arc::new(FileSetProject::new(
            root.clone(),
            std::iter::empty::<PathBuf>(),
        ));
        let analyzer = EmptyAnalyzer::new(project);
        let target = CodeUnit::new(
            ProjectFile::new(root, PathBuf::from("Target.java")),
            CodeUnitType::Class,
            "pkg",
            "Target",
        );
        let cancellation = CancellationToken::default();
        cancellation.cancel();

        let result = UsageFinder::new()
            .with_cancellation(cancellation)
            .query_with_provider(
                &analyzer,
                &[target],
                Some(&PanicCandidateProvider),
                DEFAULT_MAX_FILES,
                DEFAULT_MAX_USAGES,
            );

        assert!(result.candidate_files.is_empty());
        assert!(result.result.all_hits_including_imports().is_empty());
    }
}

macro_rules! impl_graph_usage_analyzer {
    ($strategy:ty) => {
        impl GraphUsageAnalyzer for $strategy {
            fn find_graph_usages(
                &self,
                analyzer: &dyn IAnalyzer,
                overloads: &[CodeUnit],
                scan_scope: &UsageScanScope<'_>,
                max_usages: usize,
            ) -> GraphUsageOutcome {
                <$strategy>::find_graph_usages(self, analyzer, overloads, scan_scope, max_usages)
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
    scan_scope: &UsageScanScope<'_>,
    max_usages: usize,
) -> GraphUsageOutcome {
    strategy.find_graph_usages(analyzer, overloads, scan_scope, max_usages)
}

fn graph_find_usages(
    language: Language,
    analyzer: &dyn IAnalyzer,
    overloads: &[CodeUnit],
    scan_scope: &UsageScanScope<'_>,
    max_usages: usize,
) -> GraphUsageOutcome {
    match language {
        Language::JavaScript | Language::TypeScript => graph_strategy_find_usages(
            &JsTsExportUsageGraphStrategy::new(),
            analyzer,
            overloads,
            scan_scope,
            max_usages,
        ),
        Language::Python => graph_strategy_find_usages(
            &PythonExportUsageGraphStrategy::new(),
            analyzer,
            overloads,
            scan_scope,
            max_usages,
        ),
        Language::Php => graph_strategy_find_usages(
            &PhpUsageGraphStrategy::new(),
            analyzer,
            overloads,
            scan_scope,
            max_usages,
        ),
        Language::Rust => graph_strategy_find_usages(
            &RustExportUsageGraphStrategy::new(),
            analyzer,
            overloads,
            scan_scope,
            max_usages,
        ),
        Language::Java => graph_strategy_find_usages(
            &JavaUsageGraphStrategy::new(),
            analyzer,
            overloads,
            scan_scope,
            max_usages,
        ),
        Language::CSharp => graph_strategy_find_usages(
            &CSharpUsageGraphStrategy::new(),
            analyzer,
            overloads,
            scan_scope,
            max_usages,
        ),
        Language::Cpp => graph_strategy_find_usages(
            &CppUsageGraphStrategy::new(),
            analyzer,
            overloads,
            scan_scope,
            max_usages,
        ),
        Language::Go => graph_strategy_find_usages(
            &GoUsageGraphStrategy::new(),
            analyzer,
            overloads,
            scan_scope,
            max_usages,
        ),
        Language::Scala => graph_strategy_find_usages(
            &ScalaUsageGraphStrategy::new(),
            analyzer,
            overloads,
            scan_scope,
            max_usages,
        ),
        Language::Ruby => graph_strategy_find_usages(
            &RubyUsageGraphStrategy::new(),
            analyzer,
            overloads,
            scan_scope,
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
