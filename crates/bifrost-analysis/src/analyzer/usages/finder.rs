use crate::analyzer::languages::{CandidateCtx, candidate_augmentation, language_support};
use crate::analyzer::usages::candidates::find_default_candidates_with_cancellation;
use crate::analyzer::usages::common::language_for_target;
use crate::analyzer::usages::model::FuzzyResult;
use crate::analyzer::usages::outcome::{GraphFailureReason, GraphUsageOutcome};
use crate::analyzer::usages::traits::{CandidateFileProvider, GraphUsageAnalyzer, UsageScanScope};
use crate::analyzer::{AnalyzerQueryScope, CodeUnit, IAnalyzer, Language, ProjectFile};
use crate::cancellation::CancellationToken;
use crate::hash::HashSet;
use std::collections::BTreeSet;

type FileFilter = Box<dyn Fn(&ProjectFile) -> bool + Send + Sync>;

pub const DEFAULT_MAX_FILES: usize = 1000;
pub const DEFAULT_MAX_USAGES: usize = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageQueryCompletion {
    Complete,
    Cancelled,
    CandidateFilesBudgetExhausted,
    SourceBytesBudgetExhausted,
}

pub struct QueryResult {
    pub completion: UsageQueryCompletion,
    pub candidate_files: HashSet<ProjectFile>,
    pub candidate_files_truncated: bool,
    pub source_bytes_truncated: bool,
    pub scanned_source_bytes: usize,
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
/// - JavaScript / TypeScript, Python, PHP, Rust, Java, Kotlin, C#, C++, Go, Ruby, and
///   Scala targets are routed to their graph strategy first.
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

    pub fn with_cancellation(mut self, cancellation: CancellationToken) -> Self {
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
        self.query_with_provider_and_source_budget(
            analyzer, overloads, None, max_files, max_usages, None,
        )
    }

    pub(crate) fn query_with_source_budget(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        max_files: usize,
        max_usages: usize,
        max_source_bytes: usize,
    ) -> QueryResult {
        self.query_with_provider_and_source_budget(
            analyzer,
            overloads,
            None,
            max_files,
            max_usages,
            Some(max_source_bytes),
        )
    }

    pub fn query_with_provider(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        explicit_provider: Option<&dyn CandidateFileProvider>,
        max_files: usize,
        max_usages: usize,
    ) -> QueryResult {
        self.query_with_provider_and_source_budget(
            analyzer,
            overloads,
            explicit_provider,
            max_files,
            max_usages,
            None,
        )
    }

    pub(crate) fn query_with_provider_and_source_budget(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        explicit_provider: Option<&dyn CandidateFileProvider>,
        max_files: usize,
        max_usages: usize,
        max_source_bytes: Option<usize>,
    ) -> QueryResult {
        let _query_scope = AnalyzerQueryScope::new(analyzer);
        if overloads.is_empty() {
            return QueryResult {
                completion: UsageQueryCompletion::Complete,
                candidate_files: HashSet::default(),
                candidate_files_truncated: false,
                source_bytes_truncated: false,
                scanned_source_bytes: 0,
                candidate_files_sample: None,
                result: FuzzyResult::empty_success(),
                graph_failure: None,
            };
        }
        if self.cancellation.is_cancelled() {
            return cancelled_query_result();
        }

        let target = &overloads[0];
        let _cand_scope = crate::profiling::scope("usages::candidate_discovery");
        let mut candidates = HashSet::default();
        let mut supplemental = HashSet::default();
        for overload in overloads {
            match explicit_provider {
                Some(provider) => candidates.extend(provider.find_candidates(overload, analyzer)),
                None => {
                    candidates.extend(find_default_candidates_with_cancellation(
                        overload,
                        analyzer,
                        &self.cancellation,
                    ));
                    if let Some(augmentation) = candidate_augmentation(&CandidateCtx {
                        analyzer,
                        target: overload,
                        cancellation: &self.cancellation,
                    }) {
                        candidates.extend(augmentation.protected);
                        supplemental.extend(augmentation.supplemental);
                    }
                }
            }
            if self.cancellation.is_cancelled() {
                return cancelled_query_result();
            }
        }
        // Protected files are everything discovered so far; the supplemental files join
        // only afterwards, so both budgets below drop them before touching anything here.
        let mut protected_candidates = candidates.clone();
        candidates.extend(supplemental);

        if let Some(filter) = self.file_filter.as_ref() {
            candidates.retain(|file| !self.cancellation.is_cancelled() && filter(file));
            protected_candidates.retain(|file| !self.cancellation.is_cancelled() && filter(file));
        }
        if self.cancellation.is_cancelled() {
            return cancelled_query_result();
        }

        let all_candidates = candidates.clone();
        let candidate_files_budget_exhausted = candidates.len() > max_files;
        if candidate_files_budget_exhausted {
            candidates = truncate_candidates(candidates, &protected_candidates, max_files);
        }
        let (admitted, scanned_source_bytes, source_bytes_truncated, source_admission_cancelled) =
            admit_candidates_by_source_bytes(
                analyzer,
                candidates,
                &protected_candidates,
                max_source_bytes,
                &self.cancellation,
            );
        if source_admission_cancelled {
            return cancelled_query_result();
        }
        candidates = admitted;
        let candidate_files_truncated = candidates.len() < all_candidates.len();
        let candidate_files_sample =
            candidate_files_truncated.then(|| candidate_files_sample(&all_candidates, &candidates));

        drop(_cand_scope);
        let mut graph_failure = None;
        let scan_scope = UsageScanScope::with_cancellation(
            &candidates,
            self.authoritative_scope,
            &self.cancellation,
        );
        let _graph_scope = crate::profiling::scope("usages::graph_find_usages");
        let result = match graph_find_usages(
            language_for_target(target),
            analyzer,
            overloads,
            &scan_scope,
            max_usages,
        ) {
            GraphUsageOutcome::Resolved(result) => result,
            GraphUsageOutcome::FallbackSafe(diagnostic) => {
                graph_failure = Some(diagnostic.clone());
                FuzzyResult::Failure {
                    fq_name: diagnostic.fq_name,
                    reason_kind: diagnostic.reason_kind,
                    reason: diagnostic.reason,
                }
            }
            GraphUsageOutcome::TerminalFailure(diagnostic) => {
                graph_failure = Some(diagnostic.clone());
                FuzzyResult::Failure {
                    fq_name: diagnostic.fq_name,
                    reason_kind: diagnostic.reason_kind,
                    reason: diagnostic.reason,
                }
            }
        };
        // The graph scan hands back whatever it accumulated before the token
        // tripped. Those sites are real; only their exhaustiveness is in doubt,
        // so report them alongside `Cancelled` rather than discarding them and
        // letting a caller read the empty result as proven absence.
        let cancelled = self.cancellation.is_cancelled();

        QueryResult {
            completion: if cancelled {
                UsageQueryCompletion::Cancelled
            } else if source_bytes_truncated {
                UsageQueryCompletion::SourceBytesBudgetExhausted
            } else if candidate_files_budget_exhausted {
                UsageQueryCompletion::CandidateFilesBudgetExhausted
            } else {
                UsageQueryCompletion::Complete
            },
            candidate_files: candidates,
            candidate_files_truncated,
            source_bytes_truncated,
            scanned_source_bytes,
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
        completion: UsageQueryCompletion::Cancelled,
        candidate_files: HashSet::default(),
        candidate_files_truncated: false,
        source_bytes_truncated: false,
        scanned_source_bytes: 0,
        candidate_files_sample: None,
        result: FuzzyResult::empty_success(),
        graph_failure: None,
    }
}

fn admit_candidates_by_source_bytes(
    analyzer: &dyn IAnalyzer,
    candidates: HashSet<ProjectFile>,
    protected_candidates: &HashSet<ProjectFile>,
    max_source_bytes: Option<usize>,
    cancellation: &CancellationToken,
) -> (HashSet<ProjectFile>, usize, bool, bool) {
    let Some(max_source_bytes) = max_source_bytes else {
        return (candidates, 0, false, false);
    };

    let mut ordered = candidates.iter().cloned().collect::<Vec<_>>();
    ordered.sort_by_key(|file| (!protected_candidates.contains(file), file.clone()));
    let mut admitted = HashSet::default();
    let mut scanned_source_bytes = 0usize;
    for file in ordered {
        if cancellation.is_cancelled() {
            return (HashSet::default(), 0, false, true);
        }
        let Some(source_bytes) = analyzer.indexed_source(&file).map(|source| source.len()) else {
            continue;
        };
        if scanned_source_bytes.saturating_add(source_bytes) <= max_source_bytes {
            scanned_source_bytes += source_bytes;
            admitted.insert(file);
        }
    }
    let truncated = admitted.len() < candidates.len();
    (admitted, scanned_source_bytes, truncated, false)
}

impl Default for UsageFinder {
    fn default() -> Self {
        Self::new()
    }
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
    match language_support(language) {
        Some(support) => graph_strategy_find_usages(
            support.usage_strategy(),
            analyzer,
            overloads,
            scan_scope,
            max_usages,
        ),
        None => GraphUsageOutcome::terminal_failure(
            overloads[0].fq_name(),
            GraphFailureReason::UnsupportedTargetLanguage(
                "no graph usage strategy is available for this target language",
            ),
            "UsageFinder",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::CodeUnitIndex;
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
    fn issue_1228_pre_cancelled_query_skips_candidate_discovery() {
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
        assert_eq!(result.completion, UsageQueryCompletion::Cancelled);
    }

    struct SingleCandidateProvider {
        candidate: ProjectFile,
    }

    impl CandidateFileProvider for SingleCandidateProvider {
        fn find_candidates(
            &self,
            _target: &CodeUnit,
            _analyzer: &dyn IAnalyzer,
        ) -> HashSet<ProjectFile> {
            HashSet::from_iter([self.candidate.clone()])
        }
    }

    #[test]
    fn issue_1228_cancellation_after_candidate_discovery_is_not_reported_as_empty_success() {
        let root = std::env::temp_dir();
        let project: Arc<dyn Project> = Arc::new(FileSetProject::new(
            root.clone(),
            std::iter::empty::<PathBuf>(),
        ));
        let analyzer = EmptyAnalyzer::new(project);
        let target_file = ProjectFile::new(root.clone(), PathBuf::from("Target.java"));
        let target = CodeUnit::new(target_file.clone(), CodeUnitType::Class, "pkg", "Target");
        let cancellation = CancellationToken::cancel_after_checks_for_test(2);

        let result = UsageFinder::new()
            .with_cancellation(cancellation)
            .query_with_provider(
                &analyzer,
                &[target],
                Some(&SingleCandidateProvider {
                    candidate: target_file,
                }),
                DEFAULT_MAX_FILES,
                DEFAULT_MAX_USAGES,
            );

        assert_eq!(result.completion, UsageQueryCompletion::Cancelled);
        assert!(result.candidate_files.is_empty());
        assert!(result.result.all_hits_including_imports().is_empty());
    }

    #[test]
    fn issue_1416_late_cancellation_keeps_the_hits_the_graph_scan_already_proved() {
        // The graph scan returns what it accumulated before the token tripped.
        // This used to be replaced wholesale by an empty success, so a caller
        // read "0 usages" for a symbol the scan had already proved was used.
        //
        // `cancel_after_checks_for_test` counts `is_cancelled()` calls, and the
        // number of those calls is fixed for a fixed fixture, so sweeping the
        // count deterministically visits the late-cancellation window. Before
        // the fix no count in the sweep could produce hits alongside Cancelled.
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonicalize temp dir");
        std::fs::create_dir_all(root.join("src")).expect("create src");
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"late\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lib]\npath = \"src/lib.rs\"\n",
        )
        .expect("write manifest");
        std::fs::write(
            root.join("src/lib.rs"),
            "pub mod target;\npub mod caller;\n",
        )
        .expect("write lib");
        std::fs::write(
            root.join("src/target.rs"),
            "pub fn collect_it() -> i32 {\n    1\n}\n",
        )
        .expect("write target");
        let mut caller = String::from("use crate::target::collect_it;\n");
        for index in 0..40 {
            caller.push_str(&format!(
                "pub fn call_{index}() -> i32 {{\n    collect_it()\n}}\n"
            ));
        }
        std::fs::write(root.join("src/caller.rs"), caller).expect("write caller");

        let project =
            crate::analyzer::TestProject::new(root.clone(), crate::analyzer::Language::Rust);
        let analyzer = crate::analyzer::RustAnalyzer::from_project(project);
        let target_file = ProjectFile::new(root, "src/target.rs");
        let target = analyzer
            .declarations(&target_file)
            .into_iter()
            .find(|unit| unit.identifier() == "collect_it")
            .expect("fixture declares collect_it");

        let complete = UsageFinder::new().query(
            &analyzer,
            std::slice::from_ref(&target),
            DEFAULT_MAX_FILES,
            DEFAULT_MAX_USAGES,
        );
        let complete_hits = complete.result.all_hits_including_imports().len();
        assert_eq!(complete.completion, UsageQueryCompletion::Complete);
        assert!(
            complete_hits > 0,
            "fixture must produce hits for the sweep to be meaningful"
        );

        let partial_with_hits = (1..=400).find_map(|checks| {
            let result = UsageFinder::new()
                .with_cancellation(CancellationToken::cancel_after_checks_for_test(checks))
                .query(
                    &analyzer,
                    std::slice::from_ref(&target),
                    DEFAULT_MAX_FILES,
                    DEFAULT_MAX_USAGES,
                );
            let hits = result.result.all_hits_including_imports().len();
            (result.completion == UsageQueryCompletion::Cancelled && hits > 0).then_some(hits)
        });

        let hits = partial_with_hits
            .expect("a cancelled query must be able to report the hits the scan already proved");
        assert!(
            hits <= complete_hits,
            "a partial result cannot exceed the complete one: {hits} > {complete_hits}"
        );
    }

    fn write_fixture(root: &std::path::Path, files: &[(&str, &str)]) {
        for (rel, content) in files {
            ProjectFile::new(root.to_path_buf(), rel)
                .write(content)
                .unwrap_or_else(|err| panic!("write {rel}: {err}"));
        }
    }

    fn augmentation_of(
        analyzer: &dyn IAnalyzer,
        target: &CodeUnit,
    ) -> crate::analyzer::languages::CandidateAugmentation {
        candidate_augmentation(&CandidateCtx {
            analyzer,
            target,
            cancellation: &CancellationToken::default(),
        })
        .expect("fixture target's language augments its candidates")
    }

    fn default_route_candidates(
        analyzer: &dyn IAnalyzer,
        target: &CodeUnit,
    ) -> HashSet<ProjectFile> {
        find_default_candidates_with_cancellation(target, analyzer, &CancellationToken::default())
    }

    /// A protected augmentation competes with the generic candidates for the file-count
    /// budget instead of being dropped ahead of them. `caller.rs` reaches `collect_it`
    /// through a re-export, so the import-graph walk never sees it and only Rust's own
    /// binding graph can contribute it -- exactly the file whose loss would let a
    /// truncated query report proven absence for a symbol that is used.
    #[test]
    fn a_protected_augmentation_survives_the_file_count_budget() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonicalize temp dir");
        write_fixture(
            &root,
            &[
                (
                    "Cargo.toml",
                    "[package]\nname = \"pinned\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lib]\npath = \"src/lib.rs\"\n",
                ),
                (
                    "src/lib.rs",
                    "pub mod aapp;\npub mod reexport;\npub mod target;\n",
                ),
                ("src/target.rs", "pub fn collect_it() -> i32 {\n    1\n}\n"),
                ("src/reexport.rs", "pub use crate::target::collect_it;\n"),
                ("src/aapp/mod.rs", "pub mod caller;\n"),
                (
                    "src/aapp/caller.rs",
                    "use crate::reexport::collect_it;\n\npub fn call_it() -> i32 {\n    collect_it()\n}\n",
                ),
            ],
        );

        let analyzer = crate::analyzer::RustAnalyzer::from_project(
            crate::analyzer::TestProject::new(root.clone(), Language::Rust),
        );
        let target = analyzer
            .declarations(&ProjectFile::new(root.clone(), "src/target.rs"))
            .into_iter()
            .find(|unit| unit.identifier() == "collect_it")
            .expect("fixture declares collect_it");

        let routed = default_route_candidates(&analyzer, &target);
        let augmentation = augmentation_of(&analyzer, &target);
        assert!(augmentation.supplemental.is_empty());
        let hook_only: HashSet<ProjectFile> = augmentation
            .protected
            .difference(&routed)
            .cloned()
            .collect();
        assert!(
            hook_only
                .iter()
                .any(|file| file.rel_path().ends_with("caller.rs")),
            "the re-export caller must be reachable only through Rust's augmentation: \
             routed={routed:?} augmented={:?}",
            augmentation.protected
        );

        let result = UsageFinder::new().query(
            &analyzer,
            std::slice::from_ref(&target),
            routed.len(),
            DEFAULT_MAX_USAGES,
        );

        assert_eq!(
            result.completion,
            UsageQueryCompletion::CandidateFilesBudgetExhausted
        );
        assert_eq!(result.candidate_files.len(), routed.len());
        for file in &hook_only {
            assert!(
                result.candidate_files.contains(file),
                "{file:?} was dropped although it is protected: {:?}",
                result.candidate_files
            );
        }
    }

    fn php_composer_fixture() -> (tempfile::TempDir, crate::analyzer::PhpAnalyzer, CodeUnit) {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonicalize temp dir");
        let mut files = vec![
            (
                "composer.json".to_string(),
                r#"{"autoload":{"psr-4":{"App\\":"src/"}}}"#.to_string(),
            ),
            (
                "src/Domain/Service.php".to_string(),
                "<?php\nnamespace App\\Domain;\n\nclass Service {\n    public function run(): void {}\n}\n".to_string(),
            ),
            (
                "src/Http/Controller.php".to_string(),
                "<?php\nnamespace App\\Http;\n\nuse App\\Domain\\Service;\n\nclass Controller {\n    public function handle(Service $service): void {\n        $service->run();\n    }\n}\n".to_string(),
            ),
        ];
        for index in 0..6 {
            files.push((
                format!("src/Unrelated/Widget{index}.php"),
                format!(
                    "<?php\nnamespace App\\Unrelated;\n\nclass Widget{index} {{\n    public function tick(): void {{}}\n}}\n"
                ),
            ));
        }
        let borrowed: Vec<(&str, &str)> = files
            .iter()
            .map(|(rel, content)| (rel.as_str(), content.as_str()))
            .collect();
        write_fixture(&root, &borrowed);

        let analyzer = crate::analyzer::PhpAnalyzer::from_project(
            crate::analyzer::TestProject::new(root.clone(), Language::Php),
        );
        let target = analyzer
            .declarations(&ProjectFile::new(root, "src/Domain/Service.php"))
            .into_iter()
            .find(|unit| unit.is_class())
            .expect("fixture declares the Service class");
        (temp, analyzer, target)
    }

    /// A supplemental augmentation is what the file-count budget drops first. Composer
    /// autoload visibility makes every analyzed PHP file a candidate, so a budget set to
    /// the generic candidate count must keep exactly the generic candidates and shed
    /// exactly the composer expansion -- the opposite of the protected case above.
    #[test]
    fn b_a_supplemental_augmentation_is_dropped_first_by_the_file_count_budget() {
        let (_temp, analyzer, target) = php_composer_fixture();

        let routed = default_route_candidates(&analyzer, &target);
        let augmentation = augmentation_of(&analyzer, &target);
        assert!(augmentation.protected.is_empty());
        let supplemental_only: HashSet<ProjectFile> = augmentation
            .supplemental
            .difference(&routed)
            .cloned()
            .collect();
        assert!(
            supplemental_only
                .iter()
                .any(|file| file.rel_path().starts_with("src/Unrelated")),
            "composer autoload visibility must expand to the unrelated files: {:?}",
            augmentation.supplemental
        );

        let result = UsageFinder::new().query(
            &analyzer,
            std::slice::from_ref(&target),
            routed.len(),
            DEFAULT_MAX_USAGES,
        );

        assert_eq!(
            result.completion,
            UsageQueryCompletion::CandidateFilesBudgetExhausted
        );
        assert_eq!(
            result.candidate_files, routed,
            "the budget must keep exactly the protected set"
        );
        for file in &supplemental_only {
            assert!(!result.candidate_files.contains(file), "{file:?} survived");
        }
    }

    /// PHP's augmentation abandons the whole query on cancellation rather than handing
    /// back what it accumulated, so a query cancelled anywhere in candidate discovery
    /// reports no scope at all. Only cancellation after the scope is fixed -- the #1416
    /// late window -- may report candidates, and it reports the whole scope, never a
    /// half-expanded one that a caller reading `candidate_files` would take for complete.
    #[test]
    fn c_cancellation_during_a_supplemental_augmentation_abandons_the_query() {
        let (_temp, analyzer, target) = php_composer_fixture();

        let complete = UsageFinder::new().query(
            &analyzer,
            std::slice::from_ref(&target),
            DEFAULT_MAX_FILES,
            DEFAULT_MAX_USAGES,
        );
        assert_eq!(complete.completion, UsageQueryCompletion::Complete);
        assert!(!complete.candidate_files.is_empty());

        let mut cancelled = 0usize;
        for checks in 1..=400 {
            let result = UsageFinder::new()
                .with_cancellation(CancellationToken::cancel_after_checks_for_test(checks))
                .query(
                    &analyzer,
                    std::slice::from_ref(&target),
                    DEFAULT_MAX_FILES,
                    DEFAULT_MAX_USAGES,
                );
            if result.completion != UsageQueryCompletion::Cancelled {
                continue;
            }
            if result.candidate_files.is_empty() {
                cancelled += 1;
                assert!(!result.candidate_files_truncated);
                assert!(result.result.all_hits_including_imports().is_empty());
                continue;
            }
            assert_eq!(
                result.candidate_files, complete.candidate_files,
                "a cancelled query reported a half-expanded scope at checks={checks}"
            );
        }
        assert!(
            cancelled > 0,
            "the sweep must reach the discovery-time cancellation window"
        );
    }
}
