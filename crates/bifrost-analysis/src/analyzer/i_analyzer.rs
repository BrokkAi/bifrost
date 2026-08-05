use crate::analyzer::common::display_identifier_for_target;
use crate::analyzer::store::StoreError;
use crate::analyzer::usages::{DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES, FuzzyResult, UsageFinder};
use crate::analyzer::{
    CloneSmell, CloneSmellWeights, CodeBaseMetrics, CodeUnit, CodeUnitType, CommentDensityStats,
    DeclarationInfo, DefinitionIndexHandle, ExceptionHandlingAnalysis, ExceptionSmellWeights,
    GlobalUsageDefinitionIndex, ImportAnalysisProvider, Language, ParseError, Project, ProjectFile,
    Range, SearchSymbolCandidate, SemanticDiagnostic, SignatureMetadata, SummaryFileProjection,
    TestAssertionAnalysis, TestAssertionSmell, TestAssertionWeights, TestDetectionProvider,
    TypeAliasProvider, TypeHierarchyProvider, UsageFactsIndex, metrics_from_declarations,
};
use regex::{Regex, RegexBuilder, RegexSet, RegexSetBuilder};
use std::any::Any;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, OnceLock};

#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryBatch<T> {
    pub rows: Vec<T>,
    pub inspected: usize,
    pub complete: bool,
}

impl<T> QueryBatch<T> {
    pub fn complete(rows: Vec<T>, inspected: usize) -> Self {
        Self {
            rows,
            inspected,
            complete: true,
        }
    }

    pub fn incomplete(rows: Vec<T>, inspected: usize) -> Self {
        Self {
            rows,
            inspected,
            complete: false,
        }
    }

    pub fn merge(mut self, other: Self) -> Self {
        self.rows.extend(other.rows);
        self.inspected = self.inspected.saturating_add(other.inspected);
        self.complete &= other.complete;
        self
    }
}

/// One analyzer's contribution to a batched symbol-search request.
///
/// `complete` is false when cooperative cancellation stopped enumeration.
/// Callers may retain the candidates produced before that checkpoint, but
/// must not present an incomplete batch as an authoritative search result.
#[doc(hidden)]
pub type SearchSymbolCandidates = QueryBatch<SearchSymbolCandidate>;

#[derive(Debug, Clone)]
enum CompiledSymbolPatterns {
    Set(RegexSet),
    Individual(Vec<Regex>),
}

/// A request-scoped, language-neutral symbol matcher shared by every analyzer delegate.
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct SearchSymbolPatternBatch {
    patterns: Vec<String>,
    auto_quote: bool,
    compiled: Option<CompiledSymbolPatterns>,
    complete: bool,
}

impl SearchSymbolPatternBatch {
    pub fn compile(
        patterns: Vec<String>,
        auto_quote: bool,
        cancellation: Option<&crate::CancellationToken>,
    ) -> Self {
        let mut compiled_patterns = Vec::new();
        let mut compiled_regexes = Vec::new();
        for pattern in &patterns {
            if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
                return Self {
                    patterns,
                    auto_quote,
                    compiled: None,
                    complete: false,
                };
            }
            let pattern = normalize_search_pattern(pattern, auto_quote);
            if let Ok(compiled) = RegexBuilder::new(&pattern).case_insensitive(true).build() {
                compiled_patterns.push(pattern);
                compiled_regexes.push(compiled);
            }
        }

        if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
            return Self {
                patterns,
                auto_quote,
                compiled: None,
                complete: false,
            };
        }
        let compiled = if compiled_patterns.is_empty() {
            None
        } else {
            match RegexSetBuilder::new(&compiled_patterns)
                .case_insensitive(true)
                .build()
            {
                Ok(set) => Some(CompiledSymbolPatterns::Set(set)),
                Err(_) => Some(CompiledSymbolPatterns::Individual(compiled_regexes)),
            }
        };
        Self {
            patterns,
            auto_quote,
            compiled,
            complete: true,
        }
    }

    pub fn patterns(&self) -> &[String] {
        &self.patterns
    }

    pub fn auto_quote(&self) -> bool {
        self.auto_quote
    }

    pub fn complete(&self) -> bool {
        self.complete
    }

    pub fn is_match(&self, value: &str) -> bool {
        match &self.compiled {
            Some(CompiledSymbolPatterns::Set(patterns)) => patterns.is_match(value),
            Some(CompiledSymbolPatterns::Individual(patterns)) => {
                patterns.iter().any(|pattern| pattern.is_match(value))
            }
            None => false,
        }
    }

    /// Return one safe storage substring for every pattern, or `None` when any
    /// pattern needs complete regular-expression matching. Plain ASCII
    /// identifiers are literal under the search-symbol regex contract.
    pub(crate) fn literal_ascii_substrings(&self) -> Option<Vec<&str>> {
        self.patterns
            .iter()
            .map(|pattern| {
                (!pattern.is_empty()
                    && pattern
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'))
                .then_some(pattern.as_str())
            })
            .collect()
    }
}

fn normalize_search_pattern(pattern: &str, auto_quote: bool) -> String {
    if auto_quote {
        if pattern.contains(".*") {
            pattern.to_string()
        } else {
            format!(".*?{}.*?", regex::escape(pattern))
        }
    } else {
        escape_sigil_anchors(pattern)
    }
}

/// Escape anchor metacharacters only where they form part of an identifier token.
fn escape_sigil_anchors(pattern: &str) -> String {
    let chars: Vec<char> = pattern.chars().collect();
    let mut escaped = String::with_capacity(pattern.len());
    for (index, ch) in chars.iter().enumerate() {
        let prev_is_word = index > 0
            && (chars[index - 1].is_alphanumeric() || matches!(chars[index - 1], '_' | '^'));
        let next_is_word = chars
            .get(index + 1)
            .is_some_and(|next| next.is_alphanumeric() || matches!(next, '_' | '$'));
        let unsatisfiable = match ch {
            '$' => next_is_word || prev_is_word,
            '^' => prev_is_word,
            _ => false,
        };
        if unsatisfiable {
            escaped.push('\\');
        }
        escaped.push(*ch);
    }
    escaped
}

/// Failure state for one top-level analyzer request.
///
/// The analyzer trait intentionally retains best-effort collection-returning APIs, so persisted
/// implementations record storage failures here before returning their compatibility fallback.
/// Service boundaries inspect the context before presenting a successful response.
#[doc(hidden)]
#[derive(Debug, Default)]
pub struct AnalyzerQueryContext {
    first_store_error: Mutex<Option<StoreError>>,
}

/// Analyzer-snapshot-owned query caches. The container is public only because
/// `IAnalyzer` is an extension boundary; concrete cache representations remain
/// crate-private and can evolve without coupling external analyzers to query
/// execution internals.
#[doc(hidden)]
#[derive(Default)]
pub struct AnalyzerSnapshotCaches {
    derived_layers: crate::analyzer::structural::execution::derived::SnapshotDerivedLayerCache,
    usage_graphs: crate::analyzer::usages::workspace_graph_cache::SnapshotWorkspaceUsageGraphCache,
    semantic_models: crate::analyzer::semantic_model::SemanticModelRuntimeCache,
}

impl AnalyzerSnapshotCaches {
    pub(crate) fn new(derived_layer_budget_bytes: u64) -> Self {
        Self {
            derived_layers:
                crate::analyzer::structural::execution::derived::SnapshotDerivedLayerCache::new(
                    derived_layer_budget_bytes,
                ),
            usage_graphs: crate::analyzer::usages::workspace_graph_cache::SnapshotWorkspaceUsageGraphCache::new(
                derived_layer_budget_bytes,
            ),
            semantic_models: crate::analyzer::semantic_model::SemanticModelRuntimeCache::new(
                derived_layer_budget_bytes,
            ),
        }
    }

    pub(crate) fn derived_layers(
        &self,
    ) -> &crate::analyzer::structural::execution::derived::SnapshotDerivedLayerCache {
        &self.derived_layers
    }

    pub(crate) fn usage_graphs(
        &self,
    ) -> &crate::analyzer::usages::workspace_graph_cache::SnapshotWorkspaceUsageGraphCache {
        &self.usage_graphs
    }

    pub(crate) fn semantic_models(
        &self,
    ) -> &crate::analyzer::semantic_model::SemanticModelRuntimeCache {
        &self.semantic_models
    }

    fn semantic_model_overlay(
        &self,
    ) -> Option<Arc<crate::analyzer::semantic_model::SemanticModelOverlay>> {
        self.semantic_models.overlay()
    }

    pub(crate) fn retain_dependency_discovery_evidence(
        &self,
        languages: &[crate::analyzer::Language],
        evidence: crate::analyzer::semantic_model::DependencyDiscoveryEvidence,
    ) {
        self.semantic_models
            .retain_dependency_discovery_evidence(languages, evidence);
    }

    fn dependency_discovery_evidence(
        &self,
        language: crate::analyzer::Language,
    ) -> Option<Arc<crate::analyzer::semantic_model::DependencyDiscoveryEvidence>> {
        self.semantic_models.dependency_discovery_evidence(language)
    }
}

/// Every workspace file bucketed by basename, captured by one ignore-aware
/// listing of the project tree.
///
/// This is what `WorkspaceFileResolver` needs to answer "which file does the
/// bare name `Widget.cs` mean?", and building it costs a whole-workspace walk.
/// The type lives beside the query-scope machinery rather than in
/// `path_utils` because the *cell* holding it is request-scoped analyzer state
/// (`IAnalyzer::workspace_file_index_cell`), exactly like
/// `AnalyzerSnapshotCaches`: `IAnalyzer` is a public extension boundary, so the
/// container must be nameable from the trait signature even though its
/// representation stays crate-private.
#[doc(hidden)]
#[derive(Debug, Default)]
pub struct WorkspaceFileIndex {
    root: std::path::PathBuf,
    by_basename: crate::hash::HashMap<String, Vec<ProjectFile>>,
}

/// The request-scoped, single-flight cell that holds one [`WorkspaceFileIndex`].
///
/// `Arc<OnceLock<..>>` for the same reason `top_level_class_units_by_package`
/// uses it (#1194): resolvers are built concurrently inside `rayon` closures,
/// and a check-then-build-then-store `Option` would let every thread that
/// missed the check redo the same whole-workspace walk.
#[doc(hidden)]
pub type WorkspaceFileIndexCell = Arc<OnceLock<Arc<WorkspaceFileIndex>>>;

impl WorkspaceFileIndex {
    /// One ignore-aware listing of `project`, bucketed by basename.
    pub(crate) fn build(project: &dyn Project) -> Self {
        let mut by_basename: crate::hash::HashMap<String, Vec<ProjectFile>> = Default::default();
        if let Ok(files) = project.all_files() {
            for file in files {
                let Some(name) = file.rel_path().file_name().and_then(|name| name.to_str()) else {
                    continue;
                };
                by_basename.entry(name.to_string()).or_default().push(file);
            }
            for matches in by_basename.values_mut() {
                matches.sort();
            }
        }
        Self {
            root: project.root().to_path_buf(),
            by_basename,
        }
    }

    /// Whether this index describes the workspace rooted at `root`. A shared
    /// cell is scoped to one request, and a request can legitimately touch more
    /// than one analyzer (reference differentials hold a before/after pair), so
    /// consumers must confirm the cached listing is about *their* workspace
    /// before trusting it.
    pub(crate) fn covers(&self, root: &std::path::Path) -> bool {
        self.root == root
    }

    pub(crate) fn matches(&self, basename: &str) -> Option<&[ProjectFile]> {
        self.by_basename.get(basename).map(Vec::as_slice)
    }
}

impl AnalyzerQueryContext {
    pub fn record_store_error(&self, error: StoreError) {
        let mut slot = self
            .first_store_error
            .lock()
            .expect("analyzer query error mutex poisoned");
        if slot.is_none() {
            *slot = Some(error);
        }
    }

    pub fn store_error(&self) -> Option<StoreError> {
        self.first_store_error
            .lock()
            .expect("analyzer query error mutex poisoned")
            .clone()
    }
}

pub trait IAnalyzer: Send + Sync + Any {
    /// Starts a top-level query boundary. Persisted analyzers use this to
    /// memoize filesystem liveness checks for the duration of one request.
    fn begin_query(&self, _context: &Arc<AnalyzerQueryContext>) {}

    /// Ends a top-level query boundary and releases request-scoped memoized state.
    fn end_query(&self, _context: &Arc<AnalyzerQueryContext>) {}

    /// Starts a disposable, file-local analyzer read used by broad sequential
    /// consumers such as semantic materialization.
    #[doc(hidden)]
    fn begin_streaming_file_read(&self, _file: &ProjectFile) {}

    /// Ends the matching disposable file-local read.
    #[doc(hidden)]
    fn end_streaming_file_read(&self, _file: &ProjectFile) {}

    /// Releases idle connections and page caches owned by the streaming path.
    #[doc(hidden)]
    fn release_streaming_readers(&self) {}

    /// The cell in which the active request memoizes its workspace file
    /// listing, or `None` when no query scope is open.
    ///
    /// Resolving a bare or dotted name to a workspace file needs every file's
    /// basename, which costs a full ignore-aware tree walk. That walk was paid
    /// once per `WorkspaceFileResolver`, and resolvers are constructed per call
    /// site and per symbol — so one `get_symbol_sources` request over N dotted
    /// C# names walked the repository O(N) times (#1334). The listing is stable
    /// for the duration of one request by the same argument the rest of the
    /// read cache rests on, so it is memoized against the request scope rather
    /// than a process-global cache with bespoke invalidation.
    #[doc(hidden)]
    fn workspace_file_index_cell(&self) -> Option<WorkspaceFileIndexCell> {
        None
    }

    fn top_level_declarations(&self, _file: &ProjectFile) -> Vec<CodeUnit> {
        Vec::new()
    }
    /// A compact, self-contained view for rendering one file summary. The
    /// default lets callers retain the existing method-by-method behavior.
    fn summary_file_projection(&self, _file: &ProjectFile) -> Option<Arc<SummaryFileProjection>> {
        None
    }
    fn analyzed_files(&self) -> Vec<ProjectFile> {
        Vec::new()
    }
    /// Source text retained by the analyzer generation that produced this
    /// file's declarations and byte ranges. The text is owned because a
    /// persisted analyzer may hydrate it on demand rather than retain a
    /// workspace-sized source map.
    fn indexed_source(&self, _file: &ProjectFile) -> Option<String> {
        None
    }

    /// Whether the supplied on-disk source still matches this analyzer
    /// generation. Persisted analyzers compare blob identities so freshness
    /// checks do not need to hydrate stale source text.
    fn indexed_source_matches(&self, file: &ProjectFile, source: &str) -> bool {
        self.indexed_source(file)
            .is_some_and(|indexed| indexed == source)
    }
    /// Applies language-specific rendering to an extracted source fragment.
    /// `declaration_start` is the byte offset of the declaration inside the
    /// fragment, after any attached comments. The default preserves the
    /// indexed text unchanged.
    fn render_source_fragment(
        &self,
        _code_unit: &CodeUnit,
        source: String,
        _declaration_start: usize,
    ) -> String {
        source
    }
    /// Whether `file` is one this analyzer has indexed. The default scans
    /// `analyzed_files`; concrete analyzers override with an O(1) lookup so
    /// incremental callers don't pay O(repo) per changed file.
    fn is_analyzed(&self, file: &ProjectFile) -> bool {
        self.analyzed_files()
            .iter()
            .any(|candidate| candidate == file)
    }
    fn languages(&self) -> BTreeSet<Language>;
    /// Build the expensive lazily-initialized per-generation query indexes
    /// ahead of demand (#1442). Idempotent and safe to call from a background
    /// thread: concurrent demand for the same index blocks on its one-time
    /// initialization instead of double-building, and calling this on an
    /// already-warm analyzer generation is free. The default warms nothing.
    fn warm_query_indexes(&self) {}
    /// Whether every index `warm_query_indexes` would build is already built
    /// for this analyzer generation. Analyzers with nothing to warm are
    /// always warm.
    fn query_indexes_warm(&self) -> bool {
        true
    }
    /// Drop any cached bulk working-tree identities before an explicit
    /// from-disk rebuild. Implementations without such a cache do nothing.
    fn invalidate_cached_file_identities(&self) {}
    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self
    where
        Self: Sized;
    fn update_all(&self) -> Self
    where
        Self: Sized;
    fn project(&self) -> &dyn Project;
    fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_>;
    fn all_declarations_with_primary_ranges(&self) -> Vec<(CodeUnit, Option<Range>)> {
        self.all_declarations()
            .map(|unit| {
                let range = self
                    .ranges(&unit)
                    .into_iter()
                    .min_by_key(|range| (range.start_line, range.start_byte));
                (unit, range)
            })
            .collect()
    }
    fn declarations(&self, _file: &ProjectFile) -> BTreeSet<CodeUnit> {
        BTreeSet::new()
    }
    /// Declaration-materialization provenance recorded for `file` by its
    /// language walk (issue #1476). Default empty: an analyzer that records
    /// nothing has no records, and the materialization support tables decide
    /// whether that absence means anything.
    fn materialization_records(
        &self,
        _file: &ProjectFile,
    ) -> Vec<crate::analyzer::structural::materialization::MaterializationRecord> {
        Vec::new()
    }
    fn definitions(&self, _fq_name: &str) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        Box::new(std::iter::empty())
    }

    fn global_usage_definition_index(&self) -> DefinitionIndexHandle<'_> {
        static EMPTY: OnceLock<GlobalUsageDefinitionIndex> = OnceLock::new();
        DefinitionIndexHandle::Single(EMPTY.get_or_init(GlobalUsageDefinitionIndex::default))
    }
    #[doc(hidden)]
    fn reset_global_usage_definition_index_build_count_for_test(&self) {}
    #[doc(hidden)]
    fn global_usage_definition_index_build_count_for_test(&self) -> usize {
        0
    }
    #[doc(hidden)]
    fn reset_definition_candidates_query_count_for_test(&self) {}
    #[doc(hidden)]
    fn definition_candidates_query_count_for_test(&self) -> usize {
        0
    }
    #[doc(hidden)]
    fn reset_full_declaration_scan_count_for_test(&self) {}
    #[doc(hidden)]
    fn full_declaration_scan_count_for_test(&self) -> usize {
        0
    }
    #[doc(hidden)]
    fn reset_search_candidate_hydration_count_for_test(&self) {}
    /// Declarations a symbol search hydrated into `CodeUnit`s. Bounded work
    /// means this tracks the matched answer, not the workspace (#1199).
    #[doc(hidden)]
    fn search_candidate_hydration_count_for_test(&self) -> usize {
        0
    }
    #[doc(hidden)]
    fn reset_package_declaration_scan_count_for_test(&self) {}
    #[doc(hidden)]
    fn package_declaration_scan_count_for_test(&self) -> usize {
        0
    }
    #[doc(hidden)]
    fn reset_candidate_hydration_count_for_test(&self) {}
    #[doc(hidden)]
    fn candidate_hydration_count_for_test(&self) -> usize {
        0
    }
    #[doc(hidden)]
    fn full_candidate_hydration_count_for_test(&self) -> usize {
        0
    }
    #[doc(hidden)]
    fn bulk_candidate_hydration_count_for_test(&self) -> usize {
        0
    }
    #[doc(hidden)]
    fn reset_workspace_path_scan_count_for_test(&self) {}
    #[doc(hidden)]
    fn workspace_path_scan_count_for_test(&self) -> usize {
        0
    }
    #[doc(hidden)]
    fn reset_scala_project_types_build_count_for_test(&self) {}
    #[doc(hidden)]
    fn scala_project_types_build_count_for_test(&self) -> usize {
        0
    }
    #[doc(hidden)]
    fn reset_scala_query_scan_counts_for_test(&self) {}
    #[doc(hidden)]
    fn scala_query_parse_count_for_test(&self) -> usize {
        0
    }
    #[doc(hidden)]
    fn scala_query_walk_count_for_test(&self) -> usize {
        0
    }
    fn usage_facts_index(&self) -> &UsageFactsIndex {
        static EMPTY: OnceLock<UsageFactsIndex> = OnceLock::new();
        EMPTY.get_or_init(UsageFactsIndex::default)
    }
    fn direct_children(&self, _code_unit: &CodeUnit) -> Vec<CodeUnit> {
        Vec::new()
    }
    /// Return only children declared in the same source file as `code_unit`.
    ///
    /// This differs from [`IAnalyzer::direct_children`] for analyzers whose
    /// logical hierarchy crosses file boundaries. Java package modules are the
    /// motivating case: their ordinary children include classes from every file
    /// in the package, while source-local traversals such as semantic chunking
    /// must not expand the whole package merely to discard foreign files.
    fn direct_children_in_file(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.direct_children(code_unit)
            .into_iter()
            .filter(|child| child.source() == code_unit.source())
            .collect()
    }
    /// Return the declaration node's tree-sitter kind when structured syntax
    /// for this exact code unit is available.
    fn declaration_syntax_kind(&self, _code_unit: &CodeUnit) -> Option<&'static str> {
        None
    }
    /// Return the tree-sitter parse errors recorded for `file` during the
    /// most recent `analyze_file` pass. Returns `None` when the analyzer
    /// holds no state for this file (file outside the analyzer's language,
    /// `FileState` hydrated from the persisted baseline this session and
    /// not yet re-parsed, or analysis failed); callers fall back to a fresh
    /// parse in that case. An empty `Some(...)` means the file parsed
    /// cleanly. Today's `TreeSitterAnalyzer` impl clones the cached `Vec`
    /// per call — fine on clean files (the vec is empty), but a buffer
    /// mid-edit with many errors does one alloc per request. Acceptable
    /// while the second-parse cost still dominates; revisit by switching
    /// the return type to `Option<&[ParseError]>` (needs a lifetime on the
    /// trait method) or wrapping in `Arc<[ParseError]>` if it shows up in
    /// profiles.
    fn parse_errors(&self, _file: &ProjectFile) -> Option<Vec<ParseError>> {
        None
    }

    fn semantic_diagnostics(&self, _file: &ProjectFile, _source: &str) -> Vec<SemanticDiagnostic> {
        Vec::new()
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String>;
    fn import_statements(&self, _file: &ProjectFile) -> Vec<String> {
        Vec::new()
    }
    fn enclosing_code_unit(&self, file: &ProjectFile, range: &Range) -> Option<CodeUnit>;
    fn enclosing_code_unit_for_lines(
        &self,
        file: &ProjectFile,
        start_line: usize,
        end_line: usize,
    ) -> Option<CodeUnit>;
    fn is_access_expression(&self, file: &ProjectFile, start_byte: usize, end_byte: usize) -> bool;
    fn find_nearest_declaration(
        &self,
        file: &ProjectFile,
        start_byte: usize,
        end_byte: usize,
        ident: &str,
    ) -> Option<DeclarationInfo>;
    fn ranges(&self, _code_unit: &CodeUnit) -> Vec<Range> {
        Vec::new()
    }
    /// Returns at most `max_ranges` declaration ranges, the provider rows
    /// inspected, and whether more work remained (including cancellation).
    /// Production analyzers override this so bounded semantic queries never
    /// clone an unbounded stored range set.
    #[doc(hidden)]
    fn ranges_with_limit(
        &self,
        code_unit: &CodeUnit,
        max_ranges: usize,
        cancellation: &crate::CancellationToken,
    ) -> (Vec<Range>, usize, bool) {
        if max_ranges == 0 || cancellation.is_cancelled() {
            return (Vec::new(), 0, true);
        }
        let mut ranges = self.ranges(code_unit);
        let inspected = ranges.len().min(max_ranges);
        let incomplete = ranges.len() > max_ranges || cancellation.is_cancelled();
        ranges.truncate(max_ranges);
        (ranges, inspected, incomplete)
    }
    fn get_skeleton(&self, code_unit: &CodeUnit) -> Option<String>;
    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String>;
    fn get_source(&self, code_unit: &CodeUnit, include_comments: bool) -> Option<String>;
    fn get_sources(&self, code_unit: &CodeUnit, include_comments: bool) -> BTreeSet<String>;
    fn search_definitions(&self, pattern: &str, auto_quote: bool) -> BTreeSet<CodeUnit>;
    /// `search_definitions` for one language's non-literal `pattern` whose
    /// every match is nevertheless guaranteed by the caller to contain
    /// `required_literal` as a substring. Persisted stores use the literal as
    /// a substring prefilter instead of regex-scanning the whole declaration
    /// index, and multi-language workspaces route to `language`'s delegate
    /// alone instead of fanning the query out to every delegate -- the
    /// generated suffix patterns of symbol lookup are built per language and
    /// always require their terminal segment verbatim, and the combination of
    /// a whole-index regex scan fanned out per language pair made
    /// unresolvable symbol targets take seconds (#1430, #1419).
    /// Implementations that cannot exploit the hints fall back to a plain
    /// `search_definitions`; callers must still filter candidates by language.
    fn search_definitions_with_literal(
        &self,
        pattern: &str,
        _required_literal: &str,
        _language: Language,
    ) -> BTreeSet<CodeUnit> {
        self.search_definitions(pattern, false)
    }
    /// Candidate declarations whose persisted short names match a qualified
    /// lookup input. Implementations return an empty set when they cannot
    /// answer this cheaply; callers retain their broader lookup path then.
    fn lookup_candidates_by_short_name(&self, _symbol: &str) -> BTreeSet<CodeUnit> {
        BTreeSet::new()
    }
    /// Candidate declarations *or definition-lookup-only units* (#1088: a
    /// spelling the fq lookup path resolves must be visible here too, or
    /// bare-name ambiguity silently drops it) whose persisted terminal
    /// identifier (the leaf display name, e.g. `bar` for `pkg.Foo.bar`)
    /// equals `identifier`. Backed by the partial
    /// `idx_code_units_lang_identifier_lookup` index. Implementations that
    /// cannot answer cheaply return an empty set; callers retain their
    /// broader lookup path.
    fn lookup_candidates_by_identifier(&self, _identifier: &str) -> BTreeSet<CodeUnit> {
        BTreeSet::new()
    }
    /// Search candidates with the metadata needed by `search_symbols`. The
    /// default preserves existing analyzer behavior; persisted analyzers
    /// override it with a projection that avoids full file hydration.
    fn search_symbol_candidates(
        &self,
        patterns: &SearchSymbolPatternBatch,
        cancellation: Option<&crate::CancellationToken>,
    ) -> SearchSymbolCandidates {
        let mut candidates = Vec::new();
        let mut inspected = 0usize;
        if !patterns.complete() {
            return SearchSymbolCandidates::incomplete(candidates, inspected);
        }
        for pattern in patterns.patterns() {
            if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
                return SearchSymbolCandidates::incomplete(candidates, inspected);
            }
            for code_unit in self.search_definitions(pattern, patterns.auto_quote()) {
                if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
                    return SearchSymbolCandidates::incomplete(candidates, inspected);
                }
                inspected = inspected.saturating_add(1);
                candidates.push(SearchSymbolCandidate {
                    primary_range: self
                        .ranges(&code_unit)
                        .into_iter()
                        .min_by_key(|range| (range.start_line, range.start_byte)),
                    // Structurally-evidenced suppression only: analyzers without a
                    // per-declaration taint surface default untainted here (path-based
                    // test filtering in `search_symbols` still applies), so production
                    // symbols in a file with inline tests are never hidden (#1102).
                    in_test_region: self.in_test_region(&code_unit),
                    code_unit,
                });
            }
        }
        if cancellation.is_some_and(crate::CancellationToken::is_cancelled) {
            SearchSymbolCandidates::incomplete(candidates, inspected)
        } else {
            SearchSymbolCandidates::complete(candidates, inspected)
        }
    }
    /// Cold-start substring search that runs against the persisted FTS5
    /// symbol index, without requiring `AnalyzerState` to be fully built.
    /// Implementations that have no persistence layer (or whose storage
    /// open failed) should fall back to `search_definitions(pattern, true)`,
    /// which preserves the legacy in-memory behavior.
    fn search_definitions_persisted(&self, pattern: &str) -> BTreeSet<CodeUnit> {
        self.search_definitions(pattern, true)
    }
    fn signatures(&self, _code_unit: &CodeUnit) -> Vec<String> {
        Vec::new()
    }
    fn signature_metadata(&self, _code_unit: &CodeUnit) -> Vec<SignatureMetadata> {
        Vec::new()
    }

    /// The physical parts of a declaration the language spells in several
    /// pieces (a C# `partial` type), including `code_unit` itself. `None`
    /// means this analyzer does not model partial declarations at all —
    /// which is different from `Some(vec![code_unit])`, a modeled declaration
    /// with exactly one part (issue #1475).
    fn partial_declaration_parts(&self, _code_unit: &CodeUnit) -> Option<Vec<CodeUnit>> {
        None
    }

    /// The concrete members that implement an abstract member (a Rust trait
    /// member's impl items). `None` means this analyzer does not model the
    /// implementation relation, or `code_unit` is not an abstract member it
    /// can enumerate implementations for (issue #1475).
    fn abstract_member_implementations(&self, _code_unit: &CodeUnit) -> Option<Vec<CodeUnit>> {
        None
    }

    fn get_top_level_declarations(&self, file: &ProjectFile) -> Vec<CodeUnit> {
        self.top_level_declarations(file)
    }

    fn get_analyzed_files(&self) -> BTreeSet<ProjectFile> {
        self.analyzed_files().into_iter().collect()
    }

    fn get_all_declarations(&self) -> Vec<CodeUnit> {
        self.all_declarations().collect()
    }

    fn get_declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        self.declarations(file)
    }

    fn get_definitions(&self, fq_name: &str) -> Vec<CodeUnit> {
        self.definitions(fq_name).collect()
    }

    fn get_direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        self.direct_children(code_unit)
    }

    fn import_statements_of(&self, file: &ProjectFile) -> Vec<String> {
        self.import_statements(file)
    }

    fn ranges_of(&self, code_unit: &CodeUnit) -> Vec<Range> {
        self.ranges(code_unit)
    }

    fn signatures_of(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.signatures(code_unit)
    }

    fn signature_metadata_of(&self, code_unit: &CodeUnit) -> Vec<SignatureMetadata> {
        self.signature_metadata(code_unit)
    }

    fn import_analysis_provider(&self) -> Option<&dyn ImportAnalysisProvider> {
        None
    }

    /// Import provider for one file. Composite analyzers override this to
    /// distinguish a language with no import capability from a supported
    /// language whose file simply has no imports.
    fn import_analysis_provider_for_file(
        &self,
        _file: &ProjectFile,
    ) -> Option<&dyn ImportAnalysisProvider> {
        self.import_analysis_provider()
    }

    fn type_hierarchy_provider(&self) -> Option<&dyn TypeHierarchyProvider> {
        None
    }

    fn type_alias_provider(&self) -> Option<&dyn TypeAliasProvider> {
        None
    }

    fn test_detection_provider(&self) -> Option<&dyn TestDetectionProvider> {
        None
    }

    /// Per-language structural-search capabilities (issue #328), one provider
    /// per language whose adapter has a structural spec. Languages without a
    /// spec are absent; `query_code` reports them as capability diagnostics
    /// instead of silently returning nothing.
    fn structural_search_providers(
        &self,
    ) -> Vec<&dyn crate::analyzer::structural::StructuralSearchProvider> {
        Vec::new()
    }

    /// The complete semantic declaration overlay published for this analyzer
    /// snapshot, if active semantic models have been acquired successfully.
    fn semantic_model_overlay(
        &self,
    ) -> Option<Arc<crate::analyzer::semantic_model::SemanticModelOverlay>> {
        self.snapshot_caches()
            .and_then(AnalyzerSnapshotCaches::semantic_model_overlay)
    }

    /// Dependency-discovery evidence a host retained for `language`'s
    /// ecosystem, if discovery has run against this analyzer at all. This
    /// reads what the analyzer already holds; it never triggers discovery.
    fn dependency_discovery_evidence(
        &self,
        language: crate::analyzer::Language,
    ) -> Option<Arc<crate::analyzer::semantic_model::DependencyDiscoveryEvidence>> {
        self.snapshot_caches()
            .and_then(|caches| caches.dependency_discovery_evidence(language))
    }

    /// Snapshot-owned immutable derived query layers. Concrete analyzers keep
    /// the default when they cannot bind a complete snapshot lifecycle.
    #[doc(hidden)]
    fn snapshot_caches(&self) -> Option<&AnalyzerSnapshotCaches> {
        None
    }

    /// Monotonic source generations covered by the snapshot-owned derived
    /// layer cache. A composite analyzer overrides this with one ordered entry
    /// per delegate so a change outside its primary project cannot reuse stale
    /// workspace-wide relations.
    #[doc(hidden)]
    fn snapshot_source_generations(&self) -> Box<[u64]> {
        Box::new([self.project().analysis_generation()])
    }

    /// Allocation-free freshness check for a previously captured generation
    /// vector. Composite analyzers override this to compare every delegate in
    /// the same deterministic order as [`Self::snapshot_source_generations`].
    #[doc(hidden)]
    fn snapshot_generations_match(&self, expected: &[u64]) -> bool {
        expected == [self.project().analysis_generation()]
    }

    fn autocomplete_definitions(&self, query: &str) -> Vec<CodeUnit> {
        if query.is_empty() {
            return Vec::new();
        }

        let base_results = self.search_definitions(&format!(".*?{query}.*?"), false);

        // Short prefixes additionally run a fuzzy `c.*?h.*?a.*?r` pass to
        // surface camelCase matches the strict substring wouldn't catch. Skip
        // that pass when the strict pass already saturated downstream caps:
        // every reasonable caller truncates somewhere ≤ AUTOCOMPLETE_SATURATION,
        // so the fuzzy pass can only contribute items that will be discarded.
        // This is the dominant cost on per-keystroke completion paths.
        const AUTOCOMPLETE_SATURATION: usize = 1000;
        let fuzzy_results = if query.len() < 5 && base_results.len() < AUTOCOMPLETE_SATURATION {
            let mut pattern = String::from(".*?");
            for ch in query.chars() {
                pattern.push_str(&regex::escape(&ch.to_string()));
                pattern.push_str(".*?");
            }
            self.search_definitions(&pattern, false)
        } else {
            BTreeSet::new()
        };

        let mut by_fq_name: BTreeMap<String, BTreeSet<CodeUnit>> = BTreeMap::new();
        for code_unit in base_results.into_iter().chain(fuzzy_results) {
            by_fq_name
                .entry(code_unit.fq_name())
                .or_default()
                .insert(code_unit);
        }

        let mut merged: Vec<_> = by_fq_name
            .into_values()
            .flat_map(BTreeSet::into_iter)
            .filter(|code_unit| !code_unit.is_synthetic())
            .collect();
        merged.sort_by(autocomplete_definitions_sort_comparator);
        merged
    }

    fn as_capability<T: Any>(&self) -> Option<&T>
    where
        Self: Sized,
    {
        (self as &dyn Any).downcast_ref::<T>()
    }

    /// Find call sites and references to the given overloads using the default
    /// [`UsageFinder`] strategy. The free function [`crate::analyzer::usages::find_usages`] is the
    /// equivalent for callers that hold a `&dyn IAnalyzer`.
    fn find_usages(&self, overloads: &[CodeUnit]) -> FuzzyResult
    where
        Self: Sized,
    {
        UsageFinder::new().find_usages(self, overloads, DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES)
    }

    /// Like [`Self::find_usages`] but returns the candidate file set alongside the result.
    fn query_usages(
        &self,
        overloads: &[CodeUnit],
        max_files: usize,
        max_usages: usize,
    ) -> crate::analyzer::usages::QueryResult
    where
        Self: Sized,
    {
        UsageFinder::new().query(self, overloads, max_files, max_usages)
    }

    fn metrics(&self) -> CodeBaseMetrics {
        metrics_from_declarations(self.all_declarations())
    }

    fn is_empty(&self) -> bool {
        self.all_declarations().next().is_none()
    }

    fn contains_tests(&self, _file: &ProjectFile) -> bool {
        false
    }

    /// Whether `code_unit` sits in a structurally-evidenced test region — a
    /// test-attributed item, or a declaration nested inside a `#[cfg(test)]`
    /// (or otherwise test-attributed) module/item (issue #1102).
    ///
    /// Unlike [`contains_tests`](Self::contains_tests), which classifies whole
    /// files, this is per declaration, so symbol-level test filtering can hide a
    /// file's test symbols while still surfacing its production API. Analyzers
    /// that do not thread per-declaration taint default to `false` (untainted):
    /// structurally-evidenced suppression only.
    fn in_test_region(&self, _code_unit: &CodeUnit) -> bool {
        false
    }

    /// Whether `file` is compiled only into test builds, on structural evidence
    /// that lives *outside* the file (issue #1546).
    ///
    /// This exists because Rust's sibling test-module layout puts the gate on
    /// the parent's `#[cfg(test)] mod tests;` declaration: `tests.rs` matches no
    /// path convention, sits under no test directory, and its plain helper
    /// functions carry no test attribute, so neither
    /// [`contains_tests`](Self::contains_tests) nor any path rule can see it.
    ///
    /// Unlike `contains_tests`, which answers "does this file define tests",
    /// this answers "can production code reach this file at all", so a
    /// production file full of inline `#[cfg(test)] mod tests { .. }` is `false`
    /// here while a test-only file that defines no test of its own is `true`.
    /// Analyzers whose language has no such out-of-file gate default to `false`.
    fn file_is_test_only(&self, _file: &ProjectFile) -> bool {
        false
    }

    /// Compute heuristic cognitive complexity for every function-like code
    /// unit declared in `file`, preserving source order.
    ///
    /// The default implementation returns an empty vector — analyzers that
    /// expose tree-sitter ASTs override this with a per-language scorer.
    /// Callers must treat a missing key as "not computed" rather than
    /// "complexity is zero".
    fn compute_cognitive_complexities(&self, _file: &ProjectFile) -> Vec<(CodeUnit, u32)> {
        Vec::new()
    }

    /// Comment density for a single declaration. All tree-sitter-backed
    /// languages use the shared parser-backed implementation; specialized
    /// analyzers may override it when they need compatibility behavior.
    fn comment_density(&self, code_unit: &CodeUnit) -> Option<CommentDensityStats> {
        crate::analyzer::comment_density::for_code_unit(self, code_unit)
    }

    /// Comment density for the first resolved declaration that supports it.
    /// Mirrors brokk-shared `IAnalyzer.commentDensity(String)`.
    fn comment_density_by_fq_name(&self, fq_name: &str) -> Option<CommentDensityStats> {
        self.get_definitions(fq_name)
            .into_iter()
            .find_map(|cu| self.comment_density(&cu))
    }

    /// Per-top-level-declaration comment density for a parsed source file.
    fn comment_density_by_top_level(&self, file: &ProjectFile) -> Vec<CommentDensityStats> {
        crate::analyzer::comment_density::by_top_level(self, file)
    }

    /// Detect suspicious exception-handling sites in `file` using `weights`.
    /// Analyzers without an implementation return an explicit unsupported
    /// result so callers cannot mistake missing semantics for a clean file.
    fn find_exception_handling_smells(
        &self,
        file: &ProjectFile,
        weights: ExceptionSmellWeights,
    ) -> ExceptionHandlingAnalysis {
        crate::analyzer::exception_handling::analyze_for_file(self, file, weights)
    }

    /// Detect suspicious low-value or brittle test assertions in `file`
    /// using `weights`. Default is an empty vector so analyzers that do not
    /// yet implement this heuristic stay silent.
    fn find_test_assertion_smells(
        &self,
        _file: &ProjectFile,
        _weights: TestAssertionWeights,
    ) -> Vec<TestAssertionSmell> {
        Vec::new()
    }

    /// Detect assertion-smell candidates with an optional work budget.
    /// Structured bounded implementations should override this method. The
    /// default preserves complete legacy analysis without candidate accounting.
    fn find_test_assertion_smells_limited(
        &self,
        file: &ProjectFile,
        weights: TestAssertionWeights,
        _max_candidates: usize,
    ) -> TestAssertionAnalysis {
        TestAssertionAnalysis {
            findings: self.find_test_assertion_smells(file, weights),
            inspected_candidates: None,
            truncated: false,
        }
    }

    fn find_structural_clone_smells(
        &self,
        _file: &ProjectFile,
        _weights: CloneSmellWeights,
    ) -> Vec<CloneSmell> {
        Vec::new()
    }

    fn find_structural_clone_smells_for_files(
        &self,
        files: &[ProjectFile],
        weights: CloneSmellWeights,
    ) -> Vec<CloneSmell> {
        files
            .iter()
            .flat_map(|file| self.find_structural_clone_smells(file, weights))
            .collect()
    }

    fn get_skeletons(&self, file: &ProjectFile) -> BTreeMap<CodeUnit, String> {
        let mut skeletons = BTreeMap::new();
        for symbol in self.top_level_declarations(file) {
            if let Some(skeleton) = self.get_skeleton(&symbol) {
                skeletons.insert(symbol, skeleton);
            }
        }
        skeletons
    }

    fn get_members_in_class(&self, class_unit: &CodeUnit) -> Vec<CodeUnit> {
        if !class_unit.is_class() && !class_unit.is_module() {
            return Vec::new();
        }

        self.direct_children(class_unit)
            .into_iter()
            .filter(|child| child.is_class() || child.is_function() || child.is_field())
            .collect()
    }

    fn get_test_modules(&self, files: &[ProjectFile]) -> Vec<String> {
        let mut modules: Vec<_> = files
            .iter()
            .flat_map(|file| self.top_level_declarations(file))
            .map(|code_unit| {
                if code_unit.is_module() {
                    code_unit.fq_name()
                } else {
                    code_unit.package_name().to_string()
                }
            })
            .filter(|module| !module.is_empty())
            .collect();
        modules.sort();
        modules.dedup();
        modules
    }

    fn test_files_to_code_units(&self, files: &[ProjectFile]) -> BTreeSet<CodeUnit> {
        files
            .iter()
            .flat_map(|file| self.top_level_declarations(file))
            .filter(|code_unit| {
                code_unit.is_class() || code_unit.is_function() || code_unit.is_module()
            })
            .collect()
    }

    fn get_symbols(&self, sources: &BTreeSet<CodeUnit>) -> BTreeSet<String> {
        let mut symbols = BTreeSet::new();
        for source in sources {
            symbols.insert(source.identifier().to_string());
            if source.is_class() || source.is_module() {
                for child in self.direct_children(source) {
                    symbols.insert(child.identifier().to_string());
                }
            }
        }
        symbols
    }

    fn list_symbols(&self, file: &ProjectFile) -> String {
        self.list_symbols_with_types(file, &all_code_unit_types())
    }

    fn list_top_level_symbols(&self, file: &ProjectFile) -> String {
        summarize_code_units_impl(
            self,
            &summary_root_units(self, file),
            &all_code_unit_types(),
            0,
            false,
        )
    }

    fn list_symbols_with_types(
        &self,
        file: &ProjectFile,
        types: &BTreeSet<CodeUnitType>,
    ) -> String {
        summarize_code_units_impl(self, &summary_root_units(self, file), types, 0, true)
    }

    fn parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        let parent_name = default_parent_fq_name(code_unit)?;
        self.definitions(&parent_name).next()
    }
}

/// The fully-qualified name of `code_unit`'s owner (the unit with its final
/// name segment removed), or `None` if it has no owner (a top-level or
/// synthetic file-scope unit).
///
/// The owner is a pure segment pop on the unit's structured [`FqName`], rendered
/// in its native spelling — the boundaries were recorded at construction and are
/// never re-guessed from the joined string. Every unit that reaches here carries
/// a populated `fq`: freshly-extracted units populate it at emission (M1),
/// FileState- and candidate-row-loaded cache units rebuild it from the persisted
/// segments (M3/M4). The M2-era legacy separator-scan fallback (which split the
/// joined name on the rightmost of `.`/`$`/`::`/`->`) is deleted; an empty `fq`
/// now genuinely means "no owner" rather than "not yet migrated".
pub(crate) fn default_parent_fq_name(code_unit: &CodeUnit) -> Option<String> {
    let parent = code_unit
        .fq()
        .parent()
        .filter(|parent| !parent.is_empty())?;
    let interner = crate::analyzer::fq_name::segment_interner();
    let language = crate::analyzer::common::language_for_file(code_unit.source());
    Some(parent.display_native(language, interner))
}

/// Releases request-scoped analyzer memoization on every return path.
pub struct AnalyzerQueryScope<'a> {
    analyzer: &'a dyn IAnalyzer,
    context: Arc<AnalyzerQueryContext>,
}

impl<'a> AnalyzerQueryScope<'a> {
    pub fn new(analyzer: &'a dyn IAnalyzer) -> Self {
        let context = Arc::new(AnalyzerQueryContext::default());
        analyzer.begin_query(&context);
        Self { analyzer, context }
    }

    pub fn store_error(&self) -> Option<StoreError> {
        self.context.store_error()
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn record_store_error_for_test(&self, error: StoreError) {
        self.context.record_store_error(error);
    }
}

impl Drop for AnalyzerQueryScope<'_> {
    fn drop(&mut self) {
        self.analyzer.end_query(&self.context);
    }
}

/// Releases one disposable file-local analyzer read on every return path.
/// Public for the brokk-bifrost-nlp chunker, the streaming consumer.
pub struct AnalyzerStreamingFileScope<'a> {
    analyzer: &'a dyn IAnalyzer,
    file: &'a ProjectFile,
}

impl<'a> AnalyzerStreamingFileScope<'a> {
    pub fn new(analyzer: &'a dyn IAnalyzer, file: &'a ProjectFile) -> Self {
        analyzer.begin_streaming_file_read(file);
        Self { analyzer, file }
    }
}

impl Drop for AnalyzerStreamingFileScope<'_> {
    fn drop(&mut self) {
        self.analyzer.end_streaming_file_read(self.file);
    }
}

fn summary_root_units<A: IAnalyzer + ?Sized>(analyzer: &A, file: &ProjectFile) -> Vec<CodeUnit> {
    let declarations: Vec<_> = analyzer.declarations(file).into_iter().collect();
    let declaration_set: BTreeSet<_> = declarations.iter().cloned().collect();
    let mut roots: Vec<_> = declarations
        .into_iter()
        .filter(|code_unit| {
            analyzer
                .parent_of(code_unit)
                .map(|parent| parent.is_module() || !declaration_set.contains(&parent))
                .unwrap_or(true)
        })
        .collect();
    roots.sort_by(|left, right| summary_root_order(analyzer, left, right));
    roots
}

fn summary_root_order<A: IAnalyzer + ?Sized>(
    analyzer: &A,
    left: &CodeUnit,
    right: &CodeUnit,
) -> Ordering {
    let left_range = analyzer.ranges(left).into_iter().min();
    let right_range = analyzer.ranges(right).into_iter().min();
    left_range.cmp(&right_range).then_with(|| left.cmp(right))
}

fn summarize_code_units_impl<A: IAnalyzer + ?Sized>(
    analyzer: &A,
    units: &[CodeUnit],
    types: &BTreeSet<CodeUnitType>,
    indent: usize,
    recursive: bool,
) -> String {
    let indent_str = "  ".repeat(indent);
    let mut summary = String::new();

    if indent == 0 && !units.is_empty() {
        let mut grouped: Vec<(String, Vec<CodeUnit>)> = Vec::new();
        for code_unit in units {
            if code_unit.is_anonymous() || code_unit.is_module() {
                continue;
            }

            let fq_name = code_unit.fq_name();
            let group_prefix = fq_name
                .rfind('.')
                .filter(|index| *index > 0)
                .map(|index| fq_name[..index].to_string())
                .unwrap_or_default();

            if let Some((_, group_units)) = grouped
                .iter_mut()
                .find(|(prefix, _)| prefix == &group_prefix)
            {
                group_units.push(code_unit.clone());
            } else {
                grouped.push((group_prefix, vec![code_unit.clone()]));
            }
        }

        for (group_prefix, group_units) in grouped {
            if !group_prefix.is_empty() {
                summary.push_str("# ");
                summary.push_str(&group_prefix);
                summary.push('\n');
            }

            for code_unit in group_units {
                render_symbol_summary(
                    analyzer,
                    &mut summary,
                    &code_unit,
                    types,
                    indent,
                    &indent_str,
                    recursive,
                );
            }
        }
    } else {
        for code_unit in units {
            if code_unit.is_anonymous() {
                continue;
            }
            render_symbol_summary(
                analyzer,
                &mut summary,
                code_unit,
                types,
                indent,
                &indent_str,
                recursive,
            );
        }
    }

    summary.trim_end().to_string()
}

fn render_symbol_summary<A: IAnalyzer + ?Sized>(
    analyzer: &A,
    summary: &mut String,
    code_unit: &CodeUnit,
    types: &BTreeSet<CodeUnitType>,
    indent: usize,
    indent_str: &str,
    recursive: bool,
) {
    summary.push_str(indent_str);
    summary.push_str("- ");
    summary.push_str(&display_identifier_for_target(code_unit));

    if recursive {
        let children: Vec<_> = ordered_summary_children(
            analyzer,
            code_unit,
            analyzer
                .direct_children(code_unit)
                .into_iter()
                .filter(|child| types.contains(&child.kind()))
                .collect(),
        );
        if !children.is_empty() {
            summary.push('\n');
            summary.push_str(&summarize_code_units_impl(
                analyzer,
                &children,
                types,
                indent + 1,
                recursive,
            ));
        }
    }
    summary.push('\n');
}

fn ordered_summary_children<A: IAnalyzer + ?Sized>(
    analyzer: &A,
    parent: &CodeUnit,
    children: Vec<CodeUnit>,
) -> Vec<CodeUnit> {
    if children.len() < 2 {
        return children;
    }

    let parent_start = analyzer
        .ranges(parent)
        .iter()
        .map(|range| range.start_byte)
        .min()
        .unwrap_or(usize::MAX);
    let mut ordered = Vec::with_capacity(children.len());
    ordered.extend(children.iter().filter(|child| child.is_field()).cloned());
    ordered.extend(
        children
            .iter()
            .filter(|child| !child.is_field() && child_first_start(analyzer, child) >= parent_start)
            .cloned(),
    );
    ordered.extend(
        children
            .iter()
            .filter(|child| !child.is_field() && child_first_start(analyzer, child) < parent_start)
            .cloned(),
    );
    ordered
}

fn child_first_start<A: IAnalyzer + ?Sized>(analyzer: &A, child: &CodeUnit) -> usize {
    analyzer
        .ranges(child)
        .iter()
        .map(|range| range.start_byte)
        .min()
        .unwrap_or(usize::MAX)
}

fn all_code_unit_types() -> BTreeSet<CodeUnitType> {
    [
        CodeUnitType::Class,
        CodeUnitType::Function,
        CodeUnitType::Field,
        CodeUnitType::Module,
        CodeUnitType::Macro,
    ]
    .into_iter()
    .collect()
}

fn autocomplete_definitions_sort_comparator(left: &CodeUnit, right: &CodeUnit) -> Ordering {
    autocomplete_rank(left)
        .cmp(&autocomplete_rank(right))
        .then_with(|| {
            left.fq_name()
                .to_lowercase()
                .cmp(&right.fq_name().to_lowercase())
        })
        .then_with(|| {
            left.signature()
                .unwrap_or("")
                .to_lowercase()
                .cmp(&right.signature().unwrap_or("").to_lowercase())
        })
}

fn autocomplete_rank(code_unit: &CodeUnit) -> usize {
    match code_unit.kind() {
        crate::analyzer::CodeUnitType::Class => 0,
        crate::analyzer::CodeUnitType::Function => 1,
        crate::analyzer::CodeUnitType::Field => 2,
        crate::analyzer::CodeUnitType::Macro => 3,
        crate::analyzer::CodeUnitType::Module => 4,
        crate::analyzer::CodeUnitType::FileScope => 5,
    }
}

#[cfg(test)]
mod parent_of_tests {
    use super::*;
    use crate::analyzer::ProjectFile;
    use crate::analyzer::fq_name::{FqName, SegmentId, SegmentKind, segment_interner};

    fn structured_unit(
        rel: &str,
        kind: CodeUnitType,
        package_name: &str,
        short_name: &str,
        package_segment_count: usize,
        segments: &[(&str, SegmentKind)],
    ) -> CodeUnit {
        let root = std::env::current_dir().expect("test working directory should be available");
        let source = ProjectFile::new(root, rel);
        let interner = segment_interner();
        let mut fq = FqName::new();
        for &(text, seg_kind) in segments {
            let id: SegmentId = interner.intern(text, seg_kind);
            fq.push(id);
        }
        let unit = CodeUnit::from_fq(source, kind, fq, package_segment_count, None, false);
        assert_eq!(unit.package_name(), package_name);
        assert_eq!(unit.short_name(), short_name);
        unit
    }

    fn assert_structured_parent(
        rel: &str,
        kind: CodeUnitType,
        package_name: &str,
        short_name: &str,
        package_segment_count: usize,
        segments: &[(&str, SegmentKind)],
        expected_parent: Option<&str>,
    ) {
        let unit = structured_unit(
            rel,
            kind,
            package_name,
            short_name,
            package_segment_count,
            segments,
        );
        let popped = default_parent_fq_name(&unit);
        assert_eq!(
            popped.as_deref(),
            expected_parent,
            "segment-pop owner name mismatch for {short_name:?}"
        );
    }

    #[test]
    fn cpp_namespace_head_owner_uses_structured_segments() {
        // `::` between namespaces, `.` down the owner/member tail — the mixed
        // separator the plan calls out. Both arms drop the trailing member.
        assert_structured_parent(
            "a.cpp",
            CodeUnitType::Function,
            "ns1::ns2",
            "Outer.method",
            2,
            &[
                ("ns1", SegmentKind::Package),
                ("ns2", SegmentKind::Package),
                ("Outer", SegmentKind::Type),
                ("method", SegmentKind::Member),
            ],
            Some("ns1::ns2.Outer"),
        );
    }

    #[test]
    fn cpp_namespace_component_owner_uses_structured_segments() {
        // Popping into the `::`-joined namespace head: both arms agree because
        // `::` is in the parent-of separator set (unlike the shrinking-scope
        // walk, which deliberately never descends it).
        assert_structured_parent(
            "a.cpp",
            CodeUnitType::Class,
            "ns1::ns2",
            "Outer",
            2,
            &[
                ("ns1", SegmentKind::Package),
                ("ns2", SegmentKind::Package),
                ("Outer", SegmentKind::Type),
            ],
            Some("ns1::ns2"),
        );
    }

    #[test]
    fn dotted_package_owner_uses_structured_segments() {
        assert_structured_parent(
            "a.py",
            CodeUnitType::Function,
            "pkg.mod",
            "Cls.method",
            2,
            &[
                ("pkg", SegmentKind::Package),
                ("mod", SegmentKind::Package),
                ("Cls", SegmentKind::Type),
                ("method", SegmentKind::Member),
            ],
            Some("pkg.mod.Cls"),
        );
    }

    #[test]
    fn dollar_nested_owner_uses_structured_segments() {
        // A `$`-joined nested type: dropping the member, then dropping the
        // nested type, agrees between the segment pop and the `$`/`.` scan.
        assert_structured_parent(
            "a.py",
            CodeUnitType::Field,
            "",
            "Owner$Inner.member",
            0,
            &[
                ("Owner", SegmentKind::Type),
                ("Inner", SegmentKind::Nested),
                ("member", SegmentKind::Member),
            ],
            Some("Owner$Inner"),
        );
        assert_structured_parent(
            "a.py",
            CodeUnitType::Class,
            "",
            "Owner$Inner",
            0,
            &[("Owner", SegmentKind::Type), ("Inner", SegmentKind::Nested)],
            Some("Owner"),
        );
    }

    #[test]
    fn go_import_path_member_owner_uses_structured_segments() {
        // Path components carry literal dots (`github.com`) and `/` joins; both
        // arms drop only the trailing member, so the embedded dot never splits.
        assert_structured_parent(
            "a.go",
            CodeUnitType::Function,
            "github.com/foo/bar",
            "Baz.method",
            3,
            &[
                ("github.com", SegmentKind::Path),
                ("foo", SegmentKind::Path),
                ("bar", SegmentKind::Path),
                ("Baz", SegmentKind::Type),
                ("method", SegmentKind::Member),
            ],
            Some("github.com/foo/bar.Baz"),
        );
    }

    #[test]
    fn single_segment_has_no_owner() {
        assert_structured_parent(
            "a.py",
            CodeUnitType::Class,
            "",
            "Solo",
            0,
            &[("Solo", SegmentKind::Type)],
            None,
        );
    }
}
