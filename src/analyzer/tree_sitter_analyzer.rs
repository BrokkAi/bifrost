use crate::analyzer::cognitive_complexity;
use crate::analyzer::project::{OverlayRevision, ProjectSourceOrigin, ProjectSourceSnapshot};
use crate::analyzer::store::liveness::{LivePathEntry, LivePathMap, LiveSnapshot, Liveness};
use crate::analyzer::store::query::QueryResolver;
use crate::analyzer::store::{
    AnalyzerStore, GenerationId, HierarchyStorageKey, PathSymbolRow, PersistBatchLimits,
    PersistBatchStats, PreparedParsedBlob, StoreError,
};
use crate::analyzer::{
    AnalyzerConfig, CodeBaseMetrics, CodeUnit, CodeUnitType, CppTemplateMetadata, DeclarationInfo,
    GlobalUsageDefinitionIndex, IAnalyzer, ImportInfo, Language, LanguageDialect, Project,
    ProjectFile, Range, RubyMethodDispatchMode, SearchSymbolCandidate, SignatureMetadata,
    SummaryFileProjection, UsageFactsIndex,
};
use crate::gitblob;
use crate::hash::{HashMap, HashSet, map_with_capacity, set_with_capacity};
use crate::profiling;
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
use git2::{ObjectType, Oid};
use rayon::prelude::*;
use regex::RegexBuilder;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tree_sitter::{Language as TsLanguage, Node, Parser, Tree};

const TRANSIENT_FILE_STATE_CACHE_CAPACITY: usize = 128;
// A broad usage traversal may visit more files than the small cross-request
// cache holds. Retain hydrated states for one request, then release them.
const QUERY_FILE_STATE_CACHE_CAPACITY: usize = 1_024;
const QUERY_PREPARED_SYNTAX_CACHE_CAPACITY: usize = 1_024;
const SUMMARY_FILE_PROJECTION_CACHE_CAPACITY: usize = 32;
const STORE_WRITE_IMMEDIATE_RETRIES: usize = 2;
const STORE_WRITE_RETRY_BASE_DELAY: Duration = Duration::from_millis(250);
const STORE_WRITE_RETRY_MAX_DELAY: Duration = Duration::from_secs(30);

#[cfg(test)]
static PREPARED_FAILURE_PATH: Mutex<Option<std::path::PathBuf>> = Mutex::new(None);
#[cfg(test)]
static PREPARATION_FAILURE_PATH: Mutex<Option<std::path::PathBuf>> = Mutex::new(None);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BulkFileStateSource {
    Include,
    Omit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WalkControl {
    Continue,
    SkipChildren,
}

#[derive(Clone)]
pub(crate) struct AnalyzerStoreContext {
    pub(crate) store: Arc<AnalyzerStore>,
    pub(crate) gc: Arc<crate::analyzer::store::gc::AnalyzerGcCoordinator>,
    pub(crate) liveness: Option<Arc<Liveness>>,
    pub(crate) live_paths: Arc<LivePathMap>,
    pub(crate) generations: Arc<HashMap<String, GenerationId>>,
}

pub(crate) struct StructuralSnapshotKey {
    oid: Oid,
    lang: String,
    generation: GenerationId,
}

pub(crate) fn default_store_context(project: &dyn Project) -> AnalyzerStoreContext {
    let store = AnalyzerStore::open_in_memory().expect("failed to open in-memory analyzer store");
    store_context_from_store(project, store)
}

pub(crate) fn persistent_store_context(
    project: &dyn Project,
) -> std::result::Result<AnalyzerStoreContext, StoreError> {
    let store = match project.persistence_root() {
        Some(root) => AnalyzerStore::open_for_workspace(root).map_err(|error| {
            error.context(format!(
                "opening the persisted analyzer store at {}",
                crate::analyzer::store::analyzer_db_path(root).display()
            ))
        })?,
        None => AnalyzerStore::open_in_memory()
            .map_err(|error| error.context("opening the in-memory analyzer store"))?,
    };
    Ok(store_context_from_store(project, store))
}

pub(crate) fn persistent_store_context_at(
    project: &dyn Project,
    db_path: &Path,
) -> std::result::Result<AnalyzerStoreContext, StoreError> {
    let store = AnalyzerStore::open_persistent(db_path).map_err(|error| {
        error.context(format!(
            "opening the persisted analyzer store at {}",
            db_path.display()
        ))
    })?;
    Ok(store_context_from_store(project, store))
}

fn store_context_from_store(project: &dyn Project, store: AnalyzerStore) -> AnalyzerStoreContext {
    let liveness = gitblob::discover(project.root())
        .and_then(|repo| Liveness::new(repo).ok())
        .map(Arc::new);
    AnalyzerStoreContext {
        store: Arc::new(store),
        gc: Arc::new(crate::analyzer::store::gc::AnalyzerGcCoordinator::default()),
        liveness,
        live_paths: Arc::new(LivePathMap::default()),
        generations: Arc::new(HashMap::default()),
    }
}

pub(crate) fn walk_tree_preorder<'tree>(
    root: Node<'tree>,
    include_root: bool,
    mut visit: impl FnMut(Node<'tree>) -> WalkControl,
) {
    let mut cursor = root.walk();
    let mut is_root = true;

    loop {
        let node = cursor.node();
        let should_descend = if include_root || !is_root {
            visit(node) != WalkControl::SkipChildren
        } else {
            true
        };

        if should_descend && cursor.goto_first_child() {
            is_root = false;
            continue;
        }

        loop {
            if cursor.goto_next_sibling() {
                is_root = false;
                break;
            }
            if !cursor.goto_parent() {
                return;
            }
        }
    }
}

pub(crate) fn walk_named_tree_preorder<'tree>(
    root: Node<'tree>,
    include_root: bool,
    mut visit: impl FnMut(Node<'tree>) -> WalkControl,
) {
    let mut stack = vec![(root, true)];
    while let Some((node, is_root)) = stack.pop() {
        if node.is_named() && (include_root || !is_root) && visit(node) == WalkControl::SkipChildren
        {
            continue;
        }

        for index in (0..node.named_child_count()).rev() {
            if let Some(child) = node.named_child(index) {
                stack.push((child, false));
            }
        }
    }
}

pub trait LanguageAdapter: Send + Sync + 'static {
    fn language(&self) -> Language;
    fn query_directory(&self) -> &'static str;
    fn parser_language(&self) -> TsLanguage {
        crate::analyzer::parser_language_for(self.language())
            .expect("analyzable language must have a registered parser grammar")
    }
    fn parser_language_for_file(&self, file: &ProjectFile) -> TsLanguage {
        crate::analyzer::parser_language_for_path(self.language(), file.rel_path())
            .expect("analyzable language must have a registered parser grammar")
    }
    fn storage_language_key_for_file(&self, _file: &ProjectFile) -> String {
        self.language().config_label().to_string()
    }
    fn storage_language_keys(&self) -> Vec<(String, TsLanguage)> {
        vec![(
            self.language().config_label().to_string(),
            self.parser_language(),
        )]
    }
    fn file_extension(&self) -> &'static str;
    fn normalize_full_name(&self, fq_name: &str) -> String {
        fq_name.to_string()
    }
    fn simple_type_name(&self, unit: &CodeUnit) -> String {
        unit.identifier().to_string()
    }
    /// Whether fully-qualified lookup keys are intrinsic to blob contents.
    /// Path-derived adapters must leave these projections absent because one
    /// blob may be mounted at multiple live workspace paths.
    fn persist_content_stable_lookup_keys(&self) -> bool {
        false
    }
    fn callable_arity(
        &self,
        _signature: &str,
        metadata: Option<&SignatureMetadata>,
    ) -> Option<usize> {
        metadata.map(|metadata| metadata.parameters().len())
    }
    fn callable_return_type_text<'a>(&self, _signature: &'a str) -> Option<&'a str> {
        None
    }
    fn preferred_type_candidate<'a>(&self, candidates: &'a [CodeUnit]) -> Option<&'a CodeUnit> {
        candidates.first()
    }
    fn lookup_candidate_short_names(&self, normalized_fq_name: &str) -> Vec<String> {
        lookup_suffix_candidates(normalized_fq_name, &[".", "::"])
    }
    fn is_anonymous_structure(&self, _fq_name: &str) -> bool {
        false
    }
    fn storage_content_qualifier(&self, code_unit: &CodeUnit, _content_qualifier: &str) -> String {
        code_unit.package_name().to_string()
    }
    /// Whether an ASCII substring match over the persisted content qualifier
    /// is a sound candidate filter for this adapter's normalized FQNs.
    fn persisted_content_qualifier_supports_substring_search(&self) -> bool {
        true
    }
    fn storage_file_content_qualifier(&self, package_name: &str) -> String {
        package_name.to_string()
    }
    fn hydrate_content_qualifier(&self, content_qualifier: &str, _file: &ProjectFile) -> String {
        content_qualifier.to_string()
    }
    fn should_persist_code_unit(&self, code_unit: &CodeUnit) -> bool {
        !code_unit.is_file_scope()
    }
    fn storage_contains_tests(&self, state: &FileState) -> bool {
        state.contains_tests
    }
    fn hydrate_contains_tests(&self, stored: bool, _file: &ProjectFile, _source: &str) -> bool {
        stored
    }
    fn synthesize_hydrated_units(
        &self,
        _file: &ProjectFile,
        _source: &str,
        _state: &mut FileState,
    ) {
    }
    fn path_synthetic_module_unit(&self, _file: &ProjectFile) -> Option<CodeUnit> {
        None
    }
    fn has_path_synthetic_module_units(&self) -> bool {
        false
    }
    fn path_synthetic_module_requires_imports(&self) -> bool {
        false
    }
    fn include_path_synthetic_module(&self, _has_structured_imports: bool) -> bool {
        true
    }
    fn contains_tests(
        &self,
        _file: &ProjectFile,
        _source: &str,
        _tree: &Tree,
        _parsed: &ParsedFile,
    ) -> bool {
        false
    }
    fn extract_call_receiver(&self, reference: &str) -> Option<String>;
    fn parse_file(&self, file: &ProjectFile, source: &str, tree: &Tree) -> ParsedFile;
    fn definition_priority(&self, _code_unit: &CodeUnit) -> i32 {
        0
    }
    /// Optional per-language cognitive-complexity configuration. Languages
    /// without a scoring config return `None`, which makes
    /// [`TreeSitterAnalyzer::compute_cognitive_complexities`] yield an empty
    /// result.
    fn cognitive_complexity_config(&self) -> Option<&'static cognitive_complexity::Config> {
        None
    }
    /// Optional structural-search spec (issue #328). Languages that return
    /// `Some` expose `query_code` support through
    /// [`crate::analyzer::structural::StructuralSearchProvider`].
    fn structural_spec(&self) -> Option<&'static dyn crate::analyzer::structural::StructuralSpec> {
        crate::analyzer::structural_spec_for(self.language())
    }
}

pub(crate) fn lookup_suffix_candidates(
    normalized_fq_name: &str,
    separators: &[&str],
) -> Vec<String> {
    let mut candidates = vec![normalized_fq_name.to_string()];
    let mut frontier = vec![normalized_fq_name.to_string()];
    while let Some(current) = frontier.pop() {
        for separator in separators {
            if let Some((_, suffix)) = current.split_once(separator)
                && !suffix.is_empty()
            {
                let suffix = suffix.to_string();
                if !candidates.contains(&suffix) {
                    frontier.push(suffix.clone());
                    candidates.push(suffix);
                }
            }
        }
    }
    candidates.sort_by(|left, right| left.len().cmp(&right.len()).then_with(|| left.cmp(right)));
    candidates.dedup();
    candidates
}

pub type BuildProgress = Arc<dyn Fn(BuildProgressEvent) + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildProgressPhase {
    Enumerate,
    Reconcile,
    Parse,
    Persist,
    Index,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildProgressEvent {
    pub language: Language,
    pub phase: BuildProgressPhase,
    pub completed: usize,
    pub total: usize,
    pub file: Option<ProjectFile>,
}

impl BuildProgressEvent {
    fn new(
        language: Language,
        phase: BuildProgressPhase,
        completed: usize,
        total: usize,
        file: Option<ProjectFile>,
    ) -> Self {
        Self {
            language,
            phase,
            completed,
            total,
            file,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FileState {
    pub(crate) source: String,
    pub(crate) package_name: String,
    /// Content-only qualifier persisted with a blob. Languages whose canonical
    /// package identity depends on the live path recompose it during hydration.
    pub(crate) content_qualifier: String,
    pub(crate) top_level_declarations: Vec<CodeUnit>,
    pub(crate) declarations: HashSet<CodeUnit>,
    pub(crate) definition_lookup_units: HashSet<CodeUnit>,
    pub(crate) import_statements: Vec<String>,
    pub(crate) imports: Vec<ImportInfo>,
    pub(crate) scala_exports: HashMap<CodeUnit, Vec<crate::analyzer::scala::ScalaExportInfo>>,
    pub(crate) raw_supertypes: HashMap<CodeUnit, Vec<String>>,
    pub(crate) supertype_lookup_paths: HashMap<CodeUnit, Vec<String>>,
    pub(crate) type_identifiers: HashSet<String>,
    pub(crate) signatures: HashMap<CodeUnit, Vec<String>>,
    pub(crate) signature_metadata: HashMap<CodeUnit, Vec<SignatureMetadata>>,
    pub(crate) cpp_template_metadata: HashMap<CodeUnit, CppTemplateMetadata>,
    pub(crate) ruby_method_dispatch_modes: HashMap<CodeUnit, RubyMethodDispatchMode>,
    pub(crate) ranges: HashMap<CodeUnit, Vec<Range>>,
    pub(crate) children: HashMap<CodeUnit, Vec<CodeUnit>>,
    pub(crate) scala_traits: HashSet<CodeUnit>,
    pub(crate) type_aliases: HashSet<CodeUnit>,
    pub(crate) contains_tests: bool,
    /// Tree-sitter parse errors captured during `analyze_file`. The LSP
    /// diagnostic handler reads this instead of re-parsing on every keystroke
    /// — see issue #102. `None` when the `FileState` was hydrated from the
    /// blob store (which does not carry parse_errors); the diagnostic handler
    /// falls back to a fresh parse in that case until the next `update`
    /// re-populates the field.
    pub(crate) parse_errors: Option<Vec<crate::analyzer::ParseError>>,
}

/// Immutable syntax prepared from the exact source snapshot owned by a
/// request-scoped [`FileState`]. Keeping the state alive prevents the source
/// bytes and tree from drifting apart while concurrent usage queries reuse it.
#[derive(Debug)]
pub(crate) struct PreparedSyntaxTree {
    file_state: Arc<FileState>,
    tree: Tree,
    line_starts: Vec<usize>,
    dialect: LanguageDialect,
    origin: PreparedSourceOrigin,
    overlay_revision: Option<OverlayRevision>,
}

impl PreparedSyntaxTree {
    pub(crate) fn source(&self) -> &str {
        &self.file_state.source
    }

    pub(crate) fn tree(&self) -> &Tree {
        &self.tree
    }

    pub(crate) fn declaration_node(&self, code_unit: &CodeUnit) -> Option<Node<'_>> {
        let range = self.file_state.ranges.get(code_unit)?.first()?;
        self.tree
            .root_node()
            .descendant_for_byte_range(range.start_byte, range.end_byte)
    }

    pub(crate) fn direct_children(&self, owner: &CodeUnit) -> &[CodeUnit] {
        self.file_state
            .children
            .get(owner)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    pub(crate) fn line_starts(&self) -> &[usize] {
        &self.line_starts
    }

    pub(crate) const fn dialect(&self) -> LanguageDialect {
        self.dialect
    }

    pub(crate) const fn origin(&self) -> PreparedSourceOrigin {
        self.origin
    }

    pub(crate) const fn overlay_revision(&self) -> Option<OverlayRevision> {
        self.overlay_revision
    }
}

/// How the exact source snapshot selected for a prepared syntax tree entered
/// the analyzer. The content digest remains authoritative; this marker keeps
/// disk and unsaved-overlay revisions distinct even when their bytes match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum PreparedSourceOrigin {
    Disk,
    Overlay,
}

/// The requested source snapshot exceeded a caller-supplied preparation cap.
/// `minimum_source_bytes` is the smallest size proven by the bounded read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PreparedSyntaxLimitExceeded {
    minimum_source_bytes: usize,
}

impl PreparedSyntaxLimitExceeded {
    pub(crate) const fn minimum_source_bytes(self) -> usize {
        self.minimum_source_bytes
    }
}

#[derive(Clone)]
pub(crate) struct HierarchyDeclarationFacts {
    pub(crate) declaration: CodeUnit,
    pub(crate) primary_range: Option<Range>,
    pub(crate) imports: Arc<[ImportInfo]>,
    pub(crate) raw_supertypes: Arc<[String]>,
    storage_key: Option<HierarchyStorageKey>,
}

pub(crate) struct ImportFileFacts {
    pub(crate) package_name: String,
    pub(crate) imports: Vec<ImportInfo>,
}

#[derive(Debug, Clone)]
struct DirtyFileState {
    state: Arc<FileState>,
    generation: GenerationId,
    attempts: usize,
    next_retry_at: Instant,
    terminal_stale: bool,
    _last_error: String,
}

#[derive(Debug, Default)]
struct AnalyzerRuntimeState {
    fresh_parse_errors: HashMap<ProjectFile, Vec<crate::analyzer::ParseError>>,
    dirty_file_states: Mutex<HashMap<FileStateCacheKey, DirtyFileState>>,
    dirty_path_symbol_rows: Mutex<HashMap<ProjectFile, (String, PathSymbolRow)>>,
    seeded_file_states: Vec<(FileStateCacheKey, Arc<FileState>)>,
    persistence_stats: PersistBatchStats,
}

impl AnalyzerRuntimeState {
    fn new(
        fresh_parse_errors: HashMap<ProjectFile, Vec<crate::analyzer::ParseError>>,
        dirty_file_states: HashMap<FileStateCacheKey, DirtyFileState>,
        dirty_path_symbol_rows: HashMap<ProjectFile, (String, PathSymbolRow)>,
        seeded_file_states: Vec<(FileStateCacheKey, Arc<FileState>)>,
    ) -> Self {
        Self {
            fresh_parse_errors,
            dirty_file_states: Mutex::new(dirty_file_states),
            dirty_path_symbol_rows: Mutex::new(dirty_path_symbol_rows),
            seeded_file_states,
            persistence_stats: PersistBatchStats::default(),
        }
    }

    fn seed_snapshot_file_states(&self, cache: &mut FileStateCache) {
        for (key, state) in &self.seeded_file_states {
            cache.insert(key.clone(), Arc::clone(state));
        }
    }

    fn dirty_snapshot(&self) -> HashMap<FileStateCacheKey, DirtyFileState> {
        self.dirty_file_states
            .lock()
            .expect("dirty file-state mutex poisoned")
            .clone()
    }

    fn dirty_path_symbol_snapshot(&self) -> HashMap<ProjectFile, (String, PathSymbolRow)> {
        self.dirty_path_symbol_rows
            .lock()
            .expect("dirty path-symbol mutex poisoned")
            .clone()
    }

    fn dirty_content_qualifier(&self, key: &FileStateCacheKey) -> Option<String> {
        self.dirty_file_states
            .lock()
            .expect("dirty file-state mutex poisoned")
            .get(key)
            .map(|dirty| dirty.state.content_qualifier.clone())
    }

    fn dirty_imports(&self, key: &FileStateCacheKey) -> Option<Vec<ImportInfo>> {
        self.dirty_file_states
            .lock()
            .expect("dirty file-state mutex poisoned")
            .get(key)
            .map(|dirty| dirty.state.imports.clone())
    }
}

struct ReconcileFileStates {
    files: Vec<ProjectFile>,
    replace_live_paths: bool,
    progress: Option<BuildProgress>,
    dirty_file_states: HashMap<FileStateCacheKey, DirtyFileState>,
    dirty_path_symbol_rows: HashMap<ProjectFile, (String, PathSymbolRow)>,
}

enum PreparedAnalysis {
    AllStarted,
    Ready {
        file: ProjectFile,
        prepared: Box<PreparedParsedBlob>,
    },
    PreparationFailed {
        file: ProjectFile,
        state: Arc<FileState>,
        error: String,
    },
    Unparseable(ProjectFile),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RepresentativeBlobOutcome {
    Persisted,
    Dirty,
    Unparseable,
}

#[derive(Debug, Default)]
struct PreparedInFlight {
    current_items: usize,
    current_payload_bytes: usize,
    peak_items: usize,
    peak_payload_bytes: usize,
}

impl PreparedInFlight {
    fn add(&mut self, payload_bytes: usize) {
        self.current_items = self.current_items.saturating_add(1);
        self.current_payload_bytes = self.current_payload_bytes.saturating_add(payload_bytes);
        self.peak_items = self.peak_items.max(self.current_items);
        self.peak_payload_bytes = self.peak_payload_bytes.max(self.current_payload_bytes);
    }

    fn remove(&mut self, payload_bytes: usize) {
        self.current_items = self.current_items.saturating_sub(1);
        self.current_payload_bytes = self.current_payload_bytes.saturating_sub(payload_bytes);
    }
}

type PreparedPersistenceOutcome = Option<(Arc<FileState>, Option<StoreError>)>;
type PreparedOutcomeHandler<'a> = dyn FnMut(ProjectFile, PreparedPersistenceOutcome) + 'a;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FileStateCacheKey {
    oid: Oid,
    rel_path: std::path::PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PreparedSyntaxCacheKey {
    file_state: FileStateCacheKey,
    origin: PreparedSourceOrigin,
    overlay_revision: Option<OverlayRevision>,
}

#[derive(Debug, Clone, Copy)]
struct ResolvedLiveSource {
    oid: Oid,
}

#[derive(Debug, Clone)]
struct ResolvedPreparedSource {
    oid: Oid,
    snapshot: ProjectSourceSnapshot,
}

#[derive(Debug)]
struct BoundedFileCache<T> {
    capacity: usize,
    entries: HashMap<FileStateCacheKey, Arc<T>>,
    order: VecDeque<FileStateCacheKey>,
}

type FileStateCache = BoundedFileCache<FileState>;
type SummaryFileProjectionCache = BoundedFileCache<SummaryFileProjection>;

#[derive(Debug, Default)]
struct QueryReadCache {
    contexts: Vec<Arc<crate::analyzer::AnalyzerQueryContext>>,
    analyzed_live_files: Option<Vec<ProjectFile>>,
    live_sources: HashMap<ProjectFile, Option<ResolvedLiveSource>>,
    prepared_sources: HashMap<ProjectFile, Option<ResolvedPreparedSource>>,
    file_states: HashMap<FileStateCacheKey, Arc<FileState>>,
    prepared_syntax:
        HashMap<PreparedSyntaxCacheKey, Arc<OnceLock<Option<Arc<PreparedSyntaxTree>>>>>,
}

#[derive(Debug, Clone, Copy)]
enum DefinitionRangeStart {
    Persisted(Option<usize>),
    FileState,
}

#[derive(Debug, Clone)]
struct DefinitionSortCandidate {
    unit: CodeUnit,
    range_start: DefinitionRangeStart,
}

impl QueryReadCache {
    fn begin(&mut self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        if self.contexts.is_empty() {
            self.analyzed_live_files = None;
            self.live_sources.clear();
            self.prepared_sources.clear();
            self.file_states.clear();
            self.prepared_syntax.clear();
        }
        if !self
            .contexts
            .iter()
            .any(|active| Arc::ptr_eq(active, context))
        {
            self.contexts.push(Arc::clone(context));
        }
    }

    fn end(&mut self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        self.contexts.retain(|active| !Arc::ptr_eq(active, context));
        if self.contexts.is_empty() {
            self.analyzed_live_files = None;
            self.live_sources.clear();
            self.prepared_sources.clear();
            self.file_states.clear();
            self.prepared_syntax.clear();
        }
    }

    fn is_active(&self) -> bool {
        !self.contexts.is_empty()
    }

    fn analyzed_live_files(&self) -> Option<Vec<ProjectFile>> {
        self.is_active()
            .then(|| self.analyzed_live_files.clone())
            .flatten()
    }

    fn retain_analyzed_live_files(&mut self, files: Vec<ProjectFile>) {
        if self.is_active() {
            self.analyzed_live_files = Some(files);
        }
    }

    fn file_state(&self, key: &FileStateCacheKey) -> Option<Arc<FileState>> {
        self.file_states.get(key).cloned()
    }

    fn retain_file_state(&mut self, key: FileStateCacheKey, state: Arc<FileState>) {
        if self.file_states.contains_key(&key)
            || self.file_states.len() < QUERY_FILE_STATE_CACHE_CAPACITY
        {
            self.file_states.insert(key, state);
        }
    }

    fn prepared_source(&self, file: &ProjectFile) -> Option<Option<ResolvedPreparedSource>> {
        self.prepared_sources.get(file).cloned()
    }

    fn retain_prepared_source(
        &mut self,
        file: ProjectFile,
        source: Option<ResolvedPreparedSource>,
    ) {
        if self.prepared_sources.contains_key(&file)
            || self.prepared_sources.len() < QUERY_PREPARED_SYNTAX_CACHE_CAPACITY
        {
            self.prepared_sources.insert(file, source);
        }
    }

    fn prepared_syntax_cell(
        &mut self,
        key: PreparedSyntaxCacheKey,
    ) -> Option<Arc<OnceLock<Option<Arc<PreparedSyntaxTree>>>>> {
        self.prepared_syntax_cell_with_capacity(key, QUERY_PREPARED_SYNTAX_CACHE_CAPACITY)
    }

    fn prepared_syntax_cell_with_capacity(
        &mut self,
        key: PreparedSyntaxCacheKey,
        capacity: usize,
    ) -> Option<Arc<OnceLock<Option<Arc<PreparedSyntaxTree>>>>> {
        if !self.is_active() {
            return None;
        }
        if let Some(cell) = self.prepared_syntax.get(&key) {
            return Some(Arc::clone(cell));
        }
        if self.prepared_syntax.len() >= capacity {
            return None;
        }
        let cell = Arc::new(OnceLock::new());
        self.prepared_syntax.insert(key, Arc::clone(&cell));
        Some(cell)
    }
}

impl<T> BoundedFileCache<T> {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: HashMap::default(),
            order: VecDeque::new(),
        }
    }

    fn get(&mut self, key: &FileStateCacheKey) -> Option<Arc<T>> {
        let state = Arc::clone(self.entries.get(key)?);
        self.touch(key);
        Some(state)
    }

    fn insert(&mut self, key: FileStateCacheKey, value: Arc<T>) {
        if self.capacity == 0 {
            return;
        }
        if self.entries.insert(key.clone(), value).is_some() {
            self.touch(&key);
            return;
        }
        self.order.push_back(key.clone());
        while self.entries.len() > self.capacity {
            let Some(evicted) = self.order.pop_front() else {
                break;
            };
            if self.entries.remove(&evicted).is_some() {
                break;
            }
        }
    }

    fn touch(&mut self, key: &FileStateCacheKey) {
        self.order.retain(|existing| existing != key);
        self.order.push_back(key.clone());
    }
}

#[derive(Debug, Clone)]
pub struct ParsedFile {
    pub package_name: String,
    pub content_qualifier: String,
    pub top_level_declarations: Vec<CodeUnit>,
    declarations: HashSet<CodeUnit>,
    declaration_identities: HashMap<DeclarationIdentity, usize>,
    pub definition_lookup_units: HashSet<CodeUnit>,
    pub import_statements: Vec<String>,
    pub imports: Vec<ImportInfo>,
    pub(crate) scala_exports: HashMap<CodeUnit, Vec<crate::analyzer::scala::ScalaExportInfo>>,
    pub raw_supertypes: HashMap<CodeUnit, Vec<String>>,
    pub supertype_lookup_paths: HashMap<CodeUnit, Vec<String>>,
    pub type_identifiers: HashSet<String>,
    pub signatures: HashMap<CodeUnit, Vec<String>>,
    pub signature_metadata: HashMap<CodeUnit, Vec<SignatureMetadata>>,
    pub(crate) cpp_template_metadata: HashMap<CodeUnit, CppTemplateMetadata>,
    pub ruby_method_dispatch_modes: HashMap<CodeUnit, RubyMethodDispatchMode>,
    pub scala_traits: HashSet<CodeUnit>,
    pub type_aliases: HashSet<CodeUnit>,
    pub(crate) ranges: HashMap<CodeUnit, Vec<Range>>,
    /// Physical declaration occurrences retained only for request-time navigation.
    ///
    /// Unlike `ranges`, this collection is not persisted or exposed through
    /// `IAnalyzer`: broad consumers continue to observe the preferred semantic
    /// declaration range, while explicit navigation may distinguish prototypes
    /// and bodies that share one `CodeUnit` identity.
    pub(crate) navigation_ranges: HashMap<CodeUnit, Vec<Range>>,
    pub(crate) navigation_ranges_truncated: HashSet<CodeUnit>,
    pub(crate) children: HashMap<CodeUnit, Vec<CodeUnit>>,
}

const MAX_NAVIGATION_RANGES_PER_CODE_UNIT: usize = 257;

#[derive(Debug, Clone)]
struct DeclarationIdentity(CodeUnit);

impl PartialEq for DeclarationIdentity {
    fn eq(&self, other: &Self) -> bool {
        #[cfg(test)]
        DECLARATION_IDENTITY_COMPARISON_PROBE.with(|probe| {
            if let Some(comparisons) = probe.get() {
                probe.set(Some(comparisons + 1));
            }
        });
        self.0.source() == other.0.source()
            && self.0.kind() == other.0.kind()
            && self.0.package_name() == other.0.package_name()
            && self.0.short_name() == other.0.short_name()
    }
}

impl Eq for DeclarationIdentity {}

impl Hash for DeclarationIdentity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.source().hash(state);
        self.0.kind().hash(state);
        self.0.package_name().hash(state);
        self.0.short_name().hash(state);
    }
}

#[cfg(test)]
thread_local! {
    static DECLARATION_IDENTITY_COMPARISON_PROBE: std::cell::Cell<Option<usize>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
pub(crate) fn start_declaration_identity_comparison_probe() {
    DECLARATION_IDENTITY_COMPARISON_PROBE.with(|probe| probe.set(Some(0)));
}

#[cfg(test)]
pub(crate) fn finish_declaration_identity_comparison_probe() -> usize {
    DECLARATION_IDENTITY_COMPARISON_PROBE.with(|probe| {
        probe
            .replace(None)
            .expect("declaration identity comparison probe should be active")
    })
}

impl ParsedFile {
    pub fn new(package_name: String) -> Self {
        Self {
            content_qualifier: package_name.clone(),
            package_name,
            top_level_declarations: Vec::new(),
            declarations: HashSet::default(),
            declaration_identities: HashMap::default(),
            definition_lookup_units: HashSet::default(),
            import_statements: Vec::new(),
            imports: Vec::new(),
            scala_exports: HashMap::default(),
            raw_supertypes: HashMap::default(),
            supertype_lookup_paths: HashMap::default(),
            type_identifiers: HashSet::default(),
            signatures: HashMap::default(),
            signature_metadata: HashMap::default(),
            cpp_template_metadata: HashMap::default(),
            ruby_method_dispatch_modes: HashMap::default(),
            scala_traits: HashSet::default(),
            type_aliases: HashSet::default(),
            ranges: HashMap::default(),
            navigation_ranges: HashMap::default(),
            navigation_ranges_truncated: HashSet::default(),
            children: HashMap::default(),
        }
    }

    pub fn add_code_unit(
        &mut self,
        code_unit: CodeUnit,
        node: Node<'_>,
        _source: &str,
        parent: Option<CodeUnit>,
        top_level: Option<CodeUnit>,
    ) {
        self.add_code_unit_with_range(code_unit, node_range(node), parent, top_level);
    }

    pub fn add_code_unit_with_range(
        &mut self,
        code_unit: CodeUnit,
        range: Range,
        parent: Option<CodeUnit>,
        top_level: Option<CodeUnit>,
    ) {
        self.record_navigation_range(code_unit.clone(), range);
        let inserted = self.insert_declaration(code_unit.clone());

        if inserted && parent.is_none() {
            self.top_level_declarations.push(code_unit.clone());
        }

        let ranges = self.ranges.entry(code_unit.clone()).or_default();
        if !ranges.contains(&range) {
            ranges.push(range);
        }

        if let Some(parent) = parent {
            let children = self.children.entry(parent).or_default();
            if !children.contains(&code_unit) {
                children.push(code_unit.clone());
            }
        }

        if let Some(top_level) = top_level {
            self.children.entry(top_level).or_default();
        }
    }

    /// Registers a source-backed lookup fact without exposing it through the
    /// public declaration surface.
    pub fn add_definition_lookup_unit(
        &mut self,
        code_unit: CodeUnit,
        node: Node<'_>,
        _source: &str,
    ) {
        self.definition_lookup_units.insert(code_unit.clone());
        self.ranges
            .entry(code_unit)
            .or_default()
            .push(node_range(node));
    }

    /// Registers a declaration-like code unit for analysis without giving it a source range.
    ///
    /// This is for synthetic owners that should participate in import or usage resolution but
    /// should not render as user-visible declarations in summary output.
    pub fn add_synthetic_code_unit(
        &mut self,
        code_unit: CodeUnit,
        parent: Option<CodeUnit>,
        top_level: Option<CodeUnit>,
    ) {
        let inserted = self.insert_declaration(code_unit.clone());

        if inserted && parent.is_none() {
            self.top_level_declarations.push(code_unit.clone());
        }

        if let Some(parent) = parent {
            let children = self.children.entry(parent).or_default();
            if !children.contains(&code_unit) {
                children.push(code_unit.clone());
            }
        }

        if let Some(top_level) = top_level {
            self.children.entry(top_level).or_default();
        }
    }

    pub fn add_file_scope(&mut self, file: &ProjectFile, source: &str) {
        let code_unit = CodeUnit::file_scope(file.clone());
        if !self.insert_declaration(code_unit.clone()) {
            return;
        }

        self.top_level_declarations.push(code_unit.clone());
        let line_starts = compute_line_starts(source);
        let end_line = line_starts.len().saturating_sub(1);
        self.ranges.entry(code_unit).or_default().push(Range {
            start_byte: 0,
            end_byte: source.len(),
            start_line: 0,
            end_line,
        });
    }

    pub fn replace_code_unit(
        &mut self,
        code_unit: CodeUnit,
        node: Node<'_>,
        source: &str,
        parent: Option<CodeUnit>,
        top_level: Option<CodeUnit>,
    ) {
        self.remove_code_unit(&code_unit);
        self.add_code_unit(code_unit, node, source, parent, top_level);
    }

    pub fn replace_code_unit_with_range(
        &mut self,
        code_unit: CodeUnit,
        range: Range,
        parent: Option<CodeUnit>,
        top_level: Option<CodeUnit>,
    ) {
        self.remove_code_unit(&code_unit);
        self.add_code_unit_with_range(code_unit, range, parent, top_level);
    }

    pub(crate) fn record_navigation_range(&mut self, code_unit: CodeUnit, range: Range) {
        let ranges = self.navigation_ranges.entry(code_unit.clone()).or_default();
        if ranges.contains(&range) {
            return;
        }
        if ranges.len() < MAX_NAVIGATION_RANGES_PER_CODE_UNIT {
            ranges.push(range);
        } else {
            self.navigation_ranges_truncated.insert(code_unit);
        }
    }

    pub(crate) fn declarations(&self) -> &HashSet<CodeUnit> {
        &self.declarations
    }

    pub(crate) fn contains_declaration(&self, code_unit: &CodeUnit) -> bool {
        self.declarations.contains(code_unit)
    }

    pub(crate) fn contains_declaration_identity(&self, code_unit: &CodeUnit) -> bool {
        self.declaration_identities
            .contains_key(&DeclarationIdentity(code_unit.clone()))
    }

    pub fn set_raw_supertypes(&mut self, code_unit: CodeUnit, raw_supertypes: Vec<String>) {
        self.raw_supertypes.insert(code_unit, raw_supertypes);
    }

    pub fn set_supertype_lookup_paths(&mut self, code_unit: CodeUnit, lookup_paths: Vec<String>) {
        self.supertype_lookup_paths.insert(code_unit, lookup_paths);
    }

    pub fn add_raw_supertypes(&mut self, code_unit: CodeUnit, raw_supertypes: Vec<String>) {
        let entries = self.raw_supertypes.entry(code_unit).or_default();
        for raw_supertype in raw_supertypes {
            if !entries.contains(&raw_supertype) {
                entries.push(raw_supertype);
            }
        }
    }

    pub fn add_signature(&mut self, code_unit: CodeUnit, signature: String) {
        let entries = self.signatures.entry(code_unit).or_default();
        if !entries.contains(&signature) {
            entries.push(signature);
        }
    }

    pub fn add_signature_with_metadata(
        &mut self,
        code_unit: CodeUnit,
        metadata: SignatureMetadata,
    ) {
        self.add_signature(code_unit.clone(), metadata.label().to_string());
        let entries = self.signature_metadata.entry(code_unit).or_default();
        if !entries.contains(&metadata) {
            entries.push(metadata);
        }
    }

    pub fn set_ruby_method_dispatch_mode(
        &mut self,
        code_unit: CodeUnit,
        mode: RubyMethodDispatchMode,
    ) {
        self.ruby_method_dispatch_modes.insert(code_unit, mode);
    }

    pub(crate) fn set_cpp_template_metadata(
        &mut self,
        code_unit: CodeUnit,
        metadata: CppTemplateMetadata,
    ) {
        self.cpp_template_metadata.insert(code_unit, metadata);
    }

    pub fn set_scala_trait(&mut self, code_unit: CodeUnit) {
        self.scala_traits.insert(code_unit);
    }

    pub fn add_child(&mut self, parent: CodeUnit, child: CodeUnit) {
        self.children.entry(parent).or_default().push(child);
    }

    pub fn mark_type_alias(&mut self, code_unit: CodeUnit) {
        self.type_aliases.insert(code_unit);
    }

    pub fn set_primary_range(&mut self, code_unit: &CodeUnit, range: Range) {
        self.ranges.insert(code_unit.clone(), vec![range]);
    }

    pub(crate) fn first_range_start(&self, code_unit: &CodeUnit) -> Option<usize> {
        self.ranges
            .get(code_unit)
            .and_then(|ranges| ranges.iter().map(|range| range.start_byte).min())
    }

    fn remove_code_unit(&mut self, code_unit: &CodeUnit) {
        if let Some(children) = self.children.remove(code_unit) {
            for child in children {
                self.remove_code_unit(&child);
            }
        }

        for siblings in self.children.values_mut() {
            siblings.retain(|child| child != code_unit);
        }

        self.top_level_declarations
            .retain(|existing| existing != code_unit);
        self.remove_declaration(code_unit);
        self.definition_lookup_units.remove(code_unit);
        self.raw_supertypes.remove(code_unit);
        self.supertype_lookup_paths.remove(code_unit);
        self.signatures.remove(code_unit);
        self.signature_metadata.remove(code_unit);
        self.cpp_template_metadata.remove(code_unit);
        self.ruby_method_dispatch_modes.remove(code_unit);
        self.scala_traits.remove(code_unit);
        self.type_aliases.remove(code_unit);
        self.ranges.remove(code_unit);
    }

    fn insert_declaration(&mut self, code_unit: CodeUnit) -> bool {
        if !self.declarations.insert(code_unit.clone()) {
            return false;
        }
        *self
            .declaration_identities
            .entry(DeclarationIdentity(code_unit))
            .or_default() += 1;
        true
    }

    fn remove_declaration(&mut self, code_unit: &CodeUnit) -> bool {
        if !self.declarations.remove(code_unit) {
            return false;
        }
        let identity = DeclarationIdentity(code_unit.clone());
        let remove_identity = {
            let count = self
                .declaration_identities
                .get_mut(&identity)
                .expect("inserted declaration must have a semantic identity count");
            *count = count
                .checked_sub(1)
                .expect("declaration semantic identity count must be positive");
            *count == 0
        };
        if remove_identity {
            self.declaration_identities.remove(&identity);
        }
        true
    }
}

pub struct TreeSitterAnalyzer<A> {
    project: Arc<dyn Project>,
    adapter: Arc<A>,
    config: AnalyzerConfig,
    state: Arc<AnalyzerRuntimeState>,
    /// Structural-search facts cache (issue #328). Shared across clones and
    /// incremental `update()` generations — entries are validated against a
    /// hash of the current in-memory source, so surviving stale entries are
    /// self-healing rather than wrong.
    structural_cache: Arc<crate::analyzer::structural::provider::StructuralFactsCache>,
    semantic_cache: crate::analyzer::semantic::service::CompleteSemanticArtifactCache,
    store_context: AnalyzerStoreContext,
    /// Per-request persisted read model. Live OIDs are validated once and
    /// hydrated states remain available for the graph traversal.
    query_read_cache: Arc<Mutex<QueryReadCache>>,
    #[cfg(test)]
    live_oid_validation_counts: Arc<Mutex<HashMap<ProjectFile, usize>>>,
    #[cfg(test)]
    prepared_syntax_parse_counts: Arc<Mutex<HashMap<FileStateCacheKey, usize>>>,
    transient_file_states: Arc<Mutex<FileStateCache>>,
    source_snapshot_file_states: Arc<Mutex<FileStateCache>>,
    summary_file_projections: Arc<Mutex<SummaryFileProjectionCache>>,
    global_usage_definition_index: Arc<OnceLock<Arc<GlobalUsageDefinitionIndex>>>,
    global_usage_definition_index_init: Arc<Mutex<()>>,
    global_usage_definition_fallback: Arc<GlobalUsageDefinitionIndex>,
    usage_facts_index: Arc<OnceLock<Arc<UsageFactsIndex>>>,
    usage_facts_index_init: Arc<Mutex<()>>,
    usage_facts_fallback: Arc<UsageFactsIndex>,
    full_hydration_count: Arc<AtomicUsize>,
    bulk_hydration_count: Arc<AtomicUsize>,
    sql_definitions_query_count: Arc<AtomicUsize>,
    definition_candidates_query_count: Arc<AtomicUsize>,
    enclosing_code_unit_query_count: Arc<AtomicUsize>,
    full_declaration_scan_count: Arc<AtomicUsize>,
    global_usage_definition_index_build_count: Arc<AtomicUsize>,
    workspace_path_scan_count: Arc<AtomicUsize>,
    _state: PhantomData<A>,
}

impl<A> Clone for TreeSitterAnalyzer<A> {
    fn clone(&self) -> Self {
        Self {
            project: Arc::clone(&self.project),
            adapter: Arc::clone(&self.adapter),
            config: self.config.clone(),
            state: Arc::clone(&self.state),
            structural_cache: Arc::clone(&self.structural_cache),
            semantic_cache: self.semantic_cache.clone(),
            store_context: self.store_context.clone(),
            query_read_cache: Arc::new(Mutex::new(QueryReadCache::default())),
            #[cfg(test)]
            live_oid_validation_counts: Arc::clone(&self.live_oid_validation_counts),
            #[cfg(test)]
            prepared_syntax_parse_counts: Arc::clone(&self.prepared_syntax_parse_counts),
            transient_file_states: Arc::clone(&self.transient_file_states),
            source_snapshot_file_states: Arc::clone(&self.source_snapshot_file_states),
            summary_file_projections: Arc::clone(&self.summary_file_projections),
            global_usage_definition_index: Arc::clone(&self.global_usage_definition_index),
            global_usage_definition_index_init: Arc::clone(
                &self.global_usage_definition_index_init,
            ),
            global_usage_definition_fallback: Arc::clone(&self.global_usage_definition_fallback),
            usage_facts_index: Arc::clone(&self.usage_facts_index),
            usage_facts_index_init: Arc::clone(&self.usage_facts_index_init),
            usage_facts_fallback: Arc::clone(&self.usage_facts_fallback),
            full_hydration_count: Arc::clone(&self.full_hydration_count),
            bulk_hydration_count: Arc::clone(&self.bulk_hydration_count),
            sql_definitions_query_count: Arc::clone(&self.sql_definitions_query_count),
            definition_candidates_query_count: Arc::clone(&self.definition_candidates_query_count),
            enclosing_code_unit_query_count: Arc::clone(&self.enclosing_code_unit_query_count),
            full_declaration_scan_count: Arc::clone(&self.full_declaration_scan_count),
            global_usage_definition_index_build_count: Arc::clone(
                &self.global_usage_definition_index_build_count,
            ),
            workspace_path_scan_count: Arc::clone(&self.workspace_path_scan_count),
            _state: PhantomData,
        }
    }
}

impl<A> TreeSitterAnalyzer<A> {
    pub(crate) fn clone_with_project(&self, project: Arc<dyn Project>) -> Self {
        let mut snapshot = self.clone();
        snapshot.project = project;
        snapshot
    }
}

impl<A> TreeSitterAnalyzer<A>
where
    A: LanguageAdapter,
{
    fn child_order_key(ranges: &HashMap<CodeUnit, Vec<Range>>, code_unit: &CodeUnit) -> usize {
        ranges
            .get(code_unit)
            .into_iter()
            .flatten()
            .map(|range| range.start_byte)
            .min()
            .unwrap_or(usize::MAX)
    }

    fn canonicalize_children(
        descendants: &mut Vec<CodeUnit>,
        ranges: &HashMap<CodeUnit, Vec<Range>>,
    ) {
        if descendants.len() < 2 {
            return;
        }

        let mut seen = set_with_capacity(descendants.len());
        let mut keyed = Vec::with_capacity(descendants.len());
        for child in descendants.drain(..) {
            if seen.insert(child.clone()) {
                keyed.push((Self::child_order_key(ranges, &child), child));
            }
        }

        keyed.sort_by(|(left_start, left), (right_start, right)| {
            left_start.cmp(right_start).then_with(|| left.cmp(right))
        });
        descendants.extend(keyed.into_iter().map(|(_, child)| child));
    }

    pub fn new(project: Arc<dyn Project>, adapter: A) -> Self {
        Self::new_with_config(project, adapter, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, adapter: A, config: AnalyzerConfig) -> Self {
        Self::new_internal(project, adapter, config, None, None)
            .expect("failed to initialize in-memory analyzer store")
    }

    pub(crate) fn new_with_config_storage_context_and_progress(
        project: Arc<dyn Project>,
        adapter: A,
        config: AnalyzerConfig,
        store_context: AnalyzerStoreContext,
        progress: Option<BuildProgress>,
    ) -> std::result::Result<Self, StoreError> {
        Self::new_internal(project, adapter, config, progress, Some(store_context))
    }

    pub fn new_with_progress<F>(project: Arc<dyn Project>, adapter: A, progress: F) -> Self
    where
        F: Fn(BuildProgressEvent) + Send + Sync + 'static,
    {
        Self::new_with_config_and_progress(project, adapter, AnalyzerConfig::default(), progress)
    }

    pub fn new_with_config_and_progress<F>(
        project: Arc<dyn Project>,
        adapter: A,
        config: AnalyzerConfig,
        progress: F,
    ) -> Self
    where
        F: Fn(BuildProgressEvent) + Send + Sync + 'static,
    {
        Self::new_internal(project, adapter, config, Some(Arc::new(progress)), None)
            .expect("failed to initialize in-memory analyzer store")
    }

    fn new_internal(
        project: Arc<dyn Project>,
        adapter: A,
        config: AnalyzerConfig,
        progress: Option<BuildProgress>,
        store_context: Option<AnalyzerStoreContext>,
    ) -> std::result::Result<Self, StoreError> {
        let adapter = Arc::new(adapter);
        let mut store_context =
            store_context.unwrap_or_else(|| default_store_context(project.as_ref()));
        let epochs = adapter
            .storage_language_keys()
            .into_iter()
            .map(|(storage_key, parser_language)| {
                (
                    storage_key,
                    crate::analyzer::store::epoch::epoch_for(adapter.language(), &parser_language)
                        .to_string(),
                )
            })
            .collect::<Vec<_>>();
        let generations = store_context
            .store
            .ensure_language_epoch_values(&epochs)
            .map_err(|error| error.context("publishing analyzer epochs"))?;
        store_context.generations = Arc::new(generations);
        let state = {
            let _scope = profiling::scope(format!(
                "TreeSitterAnalyzer::{:?}::new_with_config",
                adapter.language()
            ));
            Arc::new(Self::build_state(
                project.as_ref(),
                adapter.as_ref(),
                &config,
                progress,
                &store_context,
            ))
        };
        let mut source_snapshot_file_states =
            FileStateCache::new(TRANSIENT_FILE_STATE_CACHE_CAPACITY);
        state.seed_snapshot_file_states(&mut source_snapshot_file_states);

        let structural_cache = Arc::new(Self::build_structural_cache(&config));
        let semantic_cache = crate::analyzer::semantic::service::CompleteSemanticArtifactCache::new(
            config.memo_cache_budget_bytes() / 8,
        );
        Ok(Self {
            project,
            adapter,
            config,
            state,
            structural_cache,
            semantic_cache,
            store_context,
            query_read_cache: Arc::new(Mutex::new(QueryReadCache::default())),
            #[cfg(test)]
            live_oid_validation_counts: Arc::new(Mutex::new(HashMap::default())),
            #[cfg(test)]
            prepared_syntax_parse_counts: Arc::new(Mutex::new(HashMap::default())),
            transient_file_states: Arc::new(Mutex::new(FileStateCache::new(
                TRANSIENT_FILE_STATE_CACHE_CAPACITY,
            ))),
            source_snapshot_file_states: Arc::new(Mutex::new(source_snapshot_file_states)),
            summary_file_projections: Arc::new(Mutex::new(SummaryFileProjectionCache::new(
                SUMMARY_FILE_PROJECTION_CACHE_CAPACITY,
            ))),
            global_usage_definition_index: Arc::new(OnceLock::new()),
            global_usage_definition_index_init: Arc::new(Mutex::new(())),
            global_usage_definition_fallback: Arc::new(GlobalUsageDefinitionIndex::default()),
            usage_facts_index: Arc::new(OnceLock::new()),
            usage_facts_index_init: Arc::new(Mutex::new(())),
            usage_facts_fallback: Arc::new(UsageFactsIndex::default()),
            full_hydration_count: Arc::new(AtomicUsize::new(0)),
            bulk_hydration_count: Arc::new(AtomicUsize::new(0)),
            sql_definitions_query_count: Arc::new(AtomicUsize::new(0)),
            definition_candidates_query_count: Arc::new(AtomicUsize::new(0)),
            enclosing_code_unit_query_count: Arc::new(AtomicUsize::new(0)),
            full_declaration_scan_count: Arc::new(AtomicUsize::new(0)),
            global_usage_definition_index_build_count: Arc::new(AtomicUsize::new(0)),
            workspace_path_scan_count: Arc::new(AtomicUsize::new(0)),
            _state: PhantomData,
        })
    }

    /// The structural facts cache takes a slice of the shared memo budget,
    /// like the per-language memo caches do.
    fn build_structural_cache(
        config: &AnalyzerConfig,
    ) -> crate::analyzer::structural::provider::StructuralFactsCache {
        crate::analyzer::structural::provider::StructuralFactsCache::new(
            config.memo_cache_budget_bytes() / 8,
        )
    }

    pub(crate) fn structural_cache(
        &self,
    ) -> &crate::analyzer::structural::provider::StructuralFactsCache {
        &self.structural_cache
    }

    pub(crate) fn materialize_semantics_with_lowerer(
        &self,
        lowerer: &dyn crate::analyzer::semantic::service::ProgramSemanticsLowerer,
        file: &ProjectFile,
        request: &mut crate::analyzer::semantic::SemanticRequest<'_>,
    ) -> Result<
        crate::analyzer::semantic::SemanticOutcome<
            Arc<crate::analyzer::semantic::SemanticArtifact>,
        >,
        crate::analyzer::semantic::SemanticProviderError,
    > {
        crate::analyzer::semantic::service::materialize_with_lowerer(
            self,
            &self.semantic_cache,
            lowerer,
            file,
            request,
        )
    }

    /// Resolve a persistence identity for the exact source string being
    /// normalized. Hashing the supplied bytes prevents a concurrent file or
    /// overlay change from associating facts with a different live OID.
    pub(crate) fn structural_snapshot_key(
        &self,
        file: &ProjectFile,
        source: &str,
    ) -> Option<StructuralSnapshotKey> {
        if self.store_context.store.is_in_memory() {
            return None;
        }
        let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).ok()?;
        let lang = self.adapter.storage_language_key_for_file(file);
        let generation = self.store_context.generations.get(&lang).copied()?;
        Some(StructuralSnapshotKey {
            oid,
            lang,
            generation,
        })
    }

    pub(crate) fn load_structural_facts_snapshot(
        &self,
        key: &StructuralSnapshotKey,
        snapshot_version: i64,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        self.store_context.store.load_structural_facts_snapshot(
            key.oid,
            &key.lang,
            key.generation,
            snapshot_version,
        )
    }

    pub(crate) fn persist_structural_facts_snapshot(
        &self,
        key: &StructuralSnapshotKey,
        snapshot_version: i64,
        payload: &[u8],
    ) -> Result<bool, StoreError> {
        self.store_context.store.upsert_structural_facts_snapshot(
            key.oid,
            &key.lang,
            key.generation,
            snapshot_version,
            payload,
        )
    }

    pub fn project(&self) -> &dyn Project {
        self.project.as_ref()
    }

    pub fn adapter(&self) -> &A {
        self.adapter.as_ref()
    }

    fn from_state(
        project: Arc<dyn Project>,
        adapter: Arc<A>,
        config: AnalyzerConfig,
        state: AnalyzerRuntimeState,
        structural_cache: Arc<crate::analyzer::structural::provider::StructuralFactsCache>,
        semantic_cache: crate::analyzer::semantic::service::CompleteSemanticArtifactCache,
        store_context: AnalyzerStoreContext,
    ) -> Self {
        let mut source_snapshot_file_states =
            FileStateCache::new(TRANSIENT_FILE_STATE_CACHE_CAPACITY);
        state.seed_snapshot_file_states(&mut source_snapshot_file_states);
        Self {
            project,
            adapter,
            config,
            state: Arc::new(state),
            structural_cache,
            semantic_cache,
            store_context,
            query_read_cache: Arc::new(Mutex::new(QueryReadCache::default())),
            #[cfg(test)]
            live_oid_validation_counts: Arc::new(Mutex::new(HashMap::default())),
            #[cfg(test)]
            prepared_syntax_parse_counts: Arc::new(Mutex::new(HashMap::default())),
            transient_file_states: Arc::new(Mutex::new(FileStateCache::new(
                TRANSIENT_FILE_STATE_CACHE_CAPACITY,
            ))),
            source_snapshot_file_states: Arc::new(Mutex::new(source_snapshot_file_states)),
            summary_file_projections: Arc::new(Mutex::new(SummaryFileProjectionCache::new(
                SUMMARY_FILE_PROJECTION_CACHE_CAPACITY,
            ))),
            global_usage_definition_index: Arc::new(OnceLock::new()),
            global_usage_definition_index_init: Arc::new(Mutex::new(())),
            global_usage_definition_fallback: Arc::new(GlobalUsageDefinitionIndex::default()),
            usage_facts_index: Arc::new(OnceLock::new()),
            usage_facts_index_init: Arc::new(Mutex::new(())),
            usage_facts_fallback: Arc::new(UsageFactsIndex::default()),
            full_hydration_count: Arc::new(AtomicUsize::new(0)),
            bulk_hydration_count: Arc::new(AtomicUsize::new(0)),
            sql_definitions_query_count: Arc::new(AtomicUsize::new(0)),
            definition_candidates_query_count: Arc::new(AtomicUsize::new(0)),
            enclosing_code_unit_query_count: Arc::new(AtomicUsize::new(0)),
            full_declaration_scan_count: Arc::new(AtomicUsize::new(0)),
            global_usage_definition_index_build_count: Arc::new(AtomicUsize::new(0)),
            workspace_path_scan_count: Arc::new(AtomicUsize::new(0)),
            _state: PhantomData,
        }
    }

    fn build_parser(language: TsLanguage) -> Parser {
        let mut parser = Parser::new();
        parser
            .set_language(&language)
            .expect("failed to load tree-sitter language");
        parser
    }

    fn analyze_file(
        parser: &mut Parser,
        adapter: &A,
        project: &dyn Project,
        file: &ProjectFile,
    ) -> Option<FileState> {
        let source = project.read_source(file).ok()?;
        Self::analyze_source(parser, adapter, file, source)
    }

    fn analyze_source(
        parser: &mut Parser,
        adapter: &A,
        file: &ProjectFile,
        source: String,
    ) -> Option<FileState> {
        if crate::analyzer::common::is_unparseable_source(source.as_str()) {
            return None;
        }
        parser
            .set_language(&adapter.parser_language_for_file(file))
            .ok()?;
        let tree = parser.parse(source.as_str(), None)?;
        let mut parsed = adapter.parse_file(file, &source, &tree);
        parsed.add_file_scope(file, &source);
        let contains_tests = adapter.contains_tests(file, &source, &tree, &parsed);
        let mut parse_errors = Vec::new();
        collect_parse_errors(tree.root_node(), &mut parse_errors);

        Some(FileState {
            source,
            content_qualifier: parsed.content_qualifier,
            package_name: parsed.package_name,
            top_level_declarations: parsed.top_level_declarations,
            declarations: parsed.declarations,
            definition_lookup_units: parsed.definition_lookup_units,
            import_statements: parsed.import_statements,
            imports: parsed.imports,
            scala_exports: parsed.scala_exports,
            raw_supertypes: parsed.raw_supertypes,
            supertype_lookup_paths: parsed.supertype_lookup_paths,
            type_identifiers: parsed.type_identifiers,
            signatures: parsed.signatures,
            signature_metadata: parsed.signature_metadata,
            cpp_template_metadata: parsed.cpp_template_metadata,
            ruby_method_dispatch_modes: parsed.ruby_method_dispatch_modes,
            ranges: parsed.ranges,
            children: parsed.children,
            scala_traits: parsed.scala_traits,
            type_aliases: parsed.type_aliases,
            contains_tests,
            parse_errors: Some(parse_errors),
        })
    }

    pub fn structural_parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        if code_unit.is_module() {
            return None;
        }

        self.fetch_file_state(code_unit.source()).and_then(|state| {
            state.children.iter().find_map(|(parent, children)| {
                children
                    .iter()
                    .any(|child| child == code_unit)
                    .then(|| parent.clone())
            })
        })
    }

    pub fn top_level_file_scope_parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        if code_unit.is_module() {
            return None;
        }

        let state = self.fetch_file_state(code_unit.source())?;
        if !state
            .top_level_declarations
            .iter()
            .any(|declaration| declaration == code_unit)
        {
            return None;
        }

        state
            .declarations
            .iter()
            .find(|declaration| declaration.is_file_scope())
            .cloned()
    }

    fn analyze_files(
        adapter: &A,
        project: &dyn Project,
        config: &AnalyzerConfig,
        files: Vec<ProjectFile>,
        progress: Option<BuildProgress>,
    ) -> Vec<(ProjectFile, Option<FileState>)> {
        let _scope = profiling::scope(format!(
            "TreeSitterAnalyzer::{:?}::analyze_files[{}]",
            adapter.language(),
            files.len()
        ));
        if files.is_empty() {
            return Vec::new();
        }

        let total = files.len();
        let language = adapter.parser_language();
        let completed = AtomicUsize::new(0);
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(config.parallelism())
            .build()
            .expect("failed to build analyzer thread pool");

        pool.install(|| {
            files
                .into_par_iter()
                .map_init(
                    || Self::build_parser(language.clone()),
                    |parser, file| {
                        let state = Self::analyze_file(parser, adapter, project, &file);
                        if let Some(progress) = progress.as_ref() {
                            let current = completed.fetch_add(1, Ordering::Relaxed) + 1;
                            progress(BuildProgressEvent::new(
                                adapter.language(),
                                BuildProgressPhase::Parse,
                                current,
                                total,
                                Some(file.clone()),
                            ));
                        }
                        (file, state)
                    },
                )
                .collect::<Vec<_>>()
        })
    }

    fn analyze_prepare_and_persist_files(
        adapter: &A,
        project: &dyn Project,
        config: &AnalyzerConfig,
        targets: Vec<(ProjectFile, Oid, String, GenerationId)>,
        progress: Option<BuildProgress>,
        store_context: &AnalyzerStoreContext,
        mut on_outcome: impl FnMut(ProjectFile, PreparedPersistenceOutcome),
    ) -> PersistBatchStats {
        const PREPARED_CHANNEL_CAPACITY: usize = 8;
        if targets.is_empty() {
            return PersistBatchStats::default();
        }

        let total = targets.len();
        let language = adapter.parser_language();
        let completed = AtomicUsize::new(0);
        let started = AtomicUsize::new(0);
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(config.parallelism())
            .build()
            .expect("failed to build analyzer thread pool");
        let (prepared_tx, prepared_rx) = std::sync::mpsc::sync_channel(PREPARED_CHANNEL_CAPACITY);
        let producer_progress = progress.clone();
        let in_flight = Arc::new(Mutex::new(PreparedInFlight::default()));
        let mut stats = PersistBatchStats::default();
        let limits = PersistBatchLimits::PRODUCTION;
        stats.configured_max_in_flight_items = config
            .parallelism()
            .saturating_add(PREPARED_CHANNEL_CAPACITY)
            .saturating_add(limits.max_blobs);

        std::thread::scope(|scope| {
            let producer_tx = prepared_tx.clone();
            let producer_in_flight = Arc::clone(&in_flight);
            scope.spawn(move || {
                pool.install(|| {
                    targets.into_par_iter().for_each_init(
                        || Self::build_parser(language.clone()),
                        |parser, (file, oid, storage_key, generation)| {
                            let current_started = started.fetch_add(1, Ordering::SeqCst) + 1;
                            if current_started == total {
                                producer_tx
                                    .send(PreparedAnalysis::AllStarted)
                                    .expect("persistence receiver should remain connected");
                            }
                            let result = match Self::analyze_file(parser, adapter, project, &file) {
                                Some(state) => {
                                    let state = Arc::new(state);
                                    if Self::should_inject_preparation_failure_for_test(&file) {
                                        PreparedAnalysis::PreparationFailed {
                                            file,
                                            state,
                                            error: "injected preparation failure".to_string(),
                                        }
                                    } else {
                                        match AnalyzerStore::prepare_parsed_blob(
                                            oid,
                                            &storage_key,
                                            generation,
                                            adapter,
                                            Arc::clone(&state),
                                        ) {
                                            Ok(mut prepared) => {
                                                Self::inject_prepared_failure_for_test(
                                                    &file,
                                                    &mut prepared,
                                                );
                                                PreparedAnalysis::Ready {
                                                    file,
                                                    prepared: Box::new(prepared),
                                                }
                                            }
                                            Err(error) => PreparedAnalysis::PreparationFailed {
                                                file,
                                                state,
                                                error: error.to_string(),
                                            },
                                        }
                                    }
                                }
                                None => PreparedAnalysis::Unparseable(file),
                            };
                            if let Some(progress) = producer_progress.as_ref() {
                                let current = completed.fetch_add(1, Ordering::Relaxed) + 1;
                                let file = match &result {
                                    PreparedAnalysis::Ready { file, .. }
                                    | PreparedAnalysis::PreparationFailed { file, .. }
                                    | PreparedAnalysis::Unparseable(file) => file.clone(),
                                    PreparedAnalysis::AllStarted => {
                                        unreachable!("start marker is not a parse result")
                                    }
                                };
                                progress(BuildProgressEvent::new(
                                    adapter.language(),
                                    BuildProgressPhase::Parse,
                                    current,
                                    total,
                                    Some(file),
                                ));
                            }
                            if let PreparedAnalysis::Ready { prepared, .. } = &result {
                                producer_in_flight
                                    .lock()
                                    .expect("prepared in-flight mutex poisoned")
                                    .add(prepared.payload_bytes());
                            }
                            producer_tx
                                .send(result)
                                .expect("persistence receiver should remain connected");
                        },
                    );
                });
            });
            drop(prepared_tx);

            let mut pending = Vec::new();
            let mut pending_files = HashMap::default();
            let mut persist_completed = 0usize;
            let mut tail_mode = false;
            let flush = |pending: &mut Vec<PreparedParsedBlob>,
                         pending_files: &mut HashMap<(Oid, String), ProjectFile>,
                         stats: &mut PersistBatchStats,
                         persist_completed: &mut usize,
                         on_outcome: &mut PreparedOutcomeHandler<'_>| {
                if pending.is_empty() {
                    return;
                }
                let prepared = std::mem::take(pending);
                let (outcomes, batch_stats) =
                    store_context.store.persist_prepared_blobs(prepared, limits);
                *persist_completed = persist_completed.saturating_add(
                    batch_stats
                        .committed_blobs
                        .saturating_add(batch_stats.failed_blobs),
                );
                if let Some(progress) = progress.as_ref() {
                    progress(BuildProgressEvent::new(
                        adapter.language(),
                        BuildProgressPhase::Persist,
                        *persist_completed,
                        total,
                        None,
                    ));
                }
                stats.merge(batch_stats);
                for outcome in outcomes {
                    in_flight
                        .lock()
                        .expect("prepared in-flight mutex poisoned")
                        .remove(outcome.prepared.payload_bytes());
                    let key = (outcome.prepared.oid(), outcome.prepared.lang().to_string());
                    let file = pending_files
                        .remove(&key)
                        .expect("prepared outcome must retain its file envelope");
                    on_outcome(
                        file,
                        Some((Arc::clone(outcome.prepared.state()), outcome.error)),
                    );
                }
            };

            let add_ready =
                |file: ProjectFile,
                 prepared: Box<PreparedParsedBlob>,
                 pending: &mut Vec<PreparedParsedBlob>,
                 pending_files: &mut HashMap<(Oid, String), ProjectFile>| {
                    let key = (prepared.oid(), prepared.lang().to_string());
                    if pending_files.insert(key, file).is_some() {
                        panic!("duplicate prepared blob key in reconcile batch");
                    }
                    pending.push(*prepared);
                    let rows = pending.iter().fold(0usize, |total, blob| {
                        total.saturating_add(blob.logical_rows())
                    });
                    let bytes = pending.iter().fold(0usize, |total, blob| {
                        total.saturating_add(blob.payload_bytes())
                    });
                    pending.len() >= limits.max_blobs
                        || rows >= limits.max_rows
                        || bytes >= limits.max_payload_bytes
                };

            let mut deferred = None;
            loop {
                let message = match deferred.take() {
                    Some(message) => Ok(message),
                    None => prepared_rx.recv(),
                };
                match message {
                    Ok(PreparedAnalysis::AllStarted) => {
                        flush(
                            &mut pending,
                            &mut pending_files,
                            &mut stats,
                            &mut persist_completed,
                            &mut on_outcome,
                        );
                        tail_mode = true;
                    }
                    Ok(PreparedAnalysis::Ready { file, prepared }) => {
                        if add_ready(file, prepared, &mut pending, &mut pending_files) {
                            flush(
                                &mut pending,
                                &mut pending_files,
                                &mut stats,
                                &mut persist_completed,
                                &mut on_outcome,
                            );
                        }
                        if tail_mode {
                            loop {
                                match prepared_rx.try_recv() {
                                    Ok(PreparedAnalysis::Ready { file, prepared }) => {
                                        if add_ready(
                                            file,
                                            prepared,
                                            &mut pending,
                                            &mut pending_files,
                                        ) {
                                            flush(
                                                &mut pending,
                                                &mut pending_files,
                                                &mut stats,
                                                &mut persist_completed,
                                                &mut on_outcome,
                                            );
                                        }
                                    }
                                    Ok(other) => {
                                        deferred = Some(other);
                                        break;
                                    }
                                    Err(std::sync::mpsc::TryRecvError::Empty)
                                    | Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
                                }
                            }
                            flush(
                                &mut pending,
                                &mut pending_files,
                                &mut stats,
                                &mut persist_completed,
                                &mut on_outcome,
                            );
                        }
                    }
                    Ok(PreparedAnalysis::PreparationFailed { file, state, error }) => {
                        stats.failed_blobs = stats.failed_blobs.saturating_add(1);
                        persist_completed = persist_completed.saturating_add(1);
                        if let Some(progress) = progress.as_ref() {
                            progress(BuildProgressEvent::new(
                                adapter.language(),
                                BuildProgressPhase::Persist,
                                persist_completed,
                                total,
                                None,
                            ));
                        }
                        on_outcome(file, Some((state, Some(StoreError::new(error)))));
                    }
                    Ok(PreparedAnalysis::Unparseable(file)) => {
                        persist_completed = persist_completed.saturating_add(1);
                        if let Some(progress) = progress.as_ref() {
                            progress(BuildProgressEvent::new(
                                adapter.language(),
                                BuildProgressPhase::Persist,
                                persist_completed,
                                total,
                                None,
                            ));
                        }
                        on_outcome(file, None);
                    }
                    Err(std::sync::mpsc::RecvError) => {
                        flush(
                            &mut pending,
                            &mut pending_files,
                            &mut stats,
                            &mut persist_completed,
                            &mut on_outcome,
                        );
                        break;
                    }
                }
            }
        });
        let in_flight = in_flight.lock().expect("prepared in-flight mutex poisoned");
        debug_assert_eq!(in_flight.current_items, 0);
        debug_assert_eq!(in_flight.current_payload_bytes, 0);
        stats.peak_in_flight_items = in_flight.peak_items;
        stats.peak_in_flight_payload_bytes = in_flight.peak_payload_bytes;
        if profiling::enabled() {
            profiling::note(format!(
                "persist_transactions={} failed_attempts={} committed_blobs={} failed_blobs={} logical_rows={} prepared_bytes={} peak_batch_blobs={} peak_batch_rows={} peak_batch_bytes={} peak_in_flight_items={} peak_in_flight_bytes={} configured_max_in_flight_items={}",
                stats.transactions,
                stats.failed_transaction_attempts,
                stats.committed_blobs,
                stats.failed_blobs,
                stats.logical_rows,
                stats.payload_bytes,
                stats.peak_batch_blobs,
                stats.peak_batch_rows,
                stats.peak_batch_payload_bytes,
                stats.peak_in_flight_items,
                stats.peak_in_flight_payload_bytes,
                stats.configured_max_in_flight_items,
            ));
        }
        stats
    }

    fn inject_prepared_failure_for_test(file: &ProjectFile, prepared: &mut PreparedParsedBlob) {
        #[cfg(test)]
        {
            let failure_path = PREPARED_FAILURE_PATH
                .lock()
                .expect("prepared failure path mutex poisoned");
            if failure_path
                .as_ref()
                .is_some_and(|path| path == &file.abs_path())
            {
                prepared.inject_invalid_range_for_test();
            }
        }
        #[cfg(not(test))]
        let _ = (file, prepared);
    }

    fn should_inject_preparation_failure_for_test(file: &ProjectFile) -> bool {
        #[cfg(test)]
        {
            return PREPARATION_FAILURE_PATH
                .lock()
                .expect("preparation failure path mutex poisoned")
                .as_ref()
                .is_some_and(|path| path == &file.abs_path());
        }
        #[cfg(not(test))]
        {
            let _ = file;
            false
        }
    }

    fn resolve_live_oids(
        project: &dyn Project,
        files: &[ProjectFile],
        config: &AnalyzerConfig,
        store_context: &AnalyzerStoreContext,
        replace_live_paths: bool,
    ) -> Result<HashMap<ProjectFile, Oid>, String> {
        type PlannedLiveOid = Option<(ProjectFile, Oid, LivePathEntry)>;

        let plan_one = |file: &ProjectFile| -> Result<PlannedLiveOid, String> {
            let has_overlay = project.has_overlay(file);
            if !file.exists() && !has_overlay {
                return Ok(None);
            }
            let (oid, entry) = if has_overlay {
                let source = project.read_source(file).map_err(|err| err.to_string())?;
                let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes())
                    .map_err(|err| err.to_string())?;
                (oid, LivePathEntry::overlay(file.clone(), oid))
            } else if let Some(liveness) = store_context.liveness.as_ref() {
                let Some(oid) = liveness.oid_for_path(file)? else {
                    return Ok(None);
                };
                (oid, LivePathEntry::filesystem(file.clone(), oid))
            } else {
                let bytes = std::fs::read(file.abs_path()).map_err(|err| err.to_string())?;
                let oid =
                    Oid::hash_object(ObjectType::Blob, &bytes).map_err(|err| err.to_string())?;
                (oid, LivePathEntry::overlay(file.clone(), oid))
            };
            Ok(Some((file.clone(), oid, entry)))
        };
        let planned = if files.len() <= 1 {
            files.iter().map(&plan_one).collect::<Vec<_>>()
        } else {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(config.parallelism().clamp(1, files.len()))
                .build()
                .map_err(|err| format!("failed to build live OID thread pool: {err}"))?;
            pool.install(|| files.par_iter().map(&plan_one).collect::<Vec<_>>())
        };

        let mut out = map_with_capacity(files.len());
        let mut live_entries = Vec::with_capacity(files.len());
        for result in planned {
            let Some((file, oid, entry)) = result? else {
                continue;
            };
            live_entries.push(entry);
            out.insert(file, oid);
        }
        if let Some(liveness) = store_context.liveness.as_ref() {
            let _ = liveness.refresh_overlay(live_entries.iter().cloned());
        }
        if replace_live_paths {
            store_context.live_paths.replace_all(live_entries);
        } else {
            store_context.live_paths.refresh(live_entries);
        }
        Ok(out)
    }

    fn build_state(
        project: &dyn Project,
        adapter: &A,
        config: &AnalyzerConfig,
        progress: Option<BuildProgress>,
        store_context: &AnalyzerStoreContext,
    ) -> AnalyzerRuntimeState {
        let _scope = profiling::scope(format!(
            "TreeSitterAnalyzer::{:?}::build_state",
            adapter.language()
        ));

        let analyzable_files: Vec<_> = {
            let _scope = profiling::scope(format!(
                "TreeSitterAnalyzer::{:?}::enumerate_files",
                adapter.language()
            ));
            project
                .analyzable_files(adapter.language())
                .unwrap_or_default()
                .into_iter()
                .collect()
        };
        if let Some(progress) = progress.as_ref() {
            progress(BuildProgressEvent::new(
                adapter.language(),
                BuildProgressPhase::Enumerate,
                analyzable_files.len(),
                analyzable_files.len(),
                None,
            ));
        }
        let state = Self::reconcile_file_states(
            project,
            adapter,
            config,
            store_context,
            ReconcileFileStates {
                files: analyzable_files.clone(),
                replace_live_paths: true,
                progress: progress.clone(),
                dirty_file_states: HashMap::default(),
                dirty_path_symbol_rows: HashMap::default(),
            },
        );
        state
            .dirty_path_symbol_rows
            .lock()
            .expect("dirty path-symbol mutex poisoned")
            .extend(Self::sync_path_symbol_units(
                adapter,
                &analyzable_files,
                store_context,
            ));

        if let Some(progress) = progress.as_ref() {
            let total = analyzable_files.len();
            progress(BuildProgressEvent::new(
                adapter.language(),
                BuildProgressPhase::Index,
                total,
                total,
                None,
            ));
        }
        store_context
            .gc
            .schedule(project.root(), Arc::clone(&store_context.store));
        state
    }

    fn path_symbol_row(adapter: &A, file: &ProjectFile, blob_oid: Oid) -> Option<PathSymbolRow> {
        let unit = adapter.path_synthetic_module_unit(file)?;
        Some(PathSymbolRow {
            rel_path: crate::path_utils::rel_path_string(file),
            blob_oid,
            kind: unit.kind(),
            package_name: unit.package_name().to_string(),
            short_name: unit.short_name().to_string(),
            exact_fqn: unit.fq_name(),
            normalized_fqn: adapter.normalize_full_name(&unit.fq_name()),
        })
    }

    fn sync_path_symbol_units(
        adapter: &A,
        files: &[ProjectFile],
        store_context: &AnalyzerStoreContext,
    ) -> HashMap<ProjectFile, (String, PathSymbolRow)> {
        if !adapter.has_path_synthetic_module_units() {
            return HashMap::default();
        }

        let snapshot = store_context.live_paths.snapshot();
        let mut rows_by_language: HashMap<String, Vec<(ProjectFile, PathSymbolRow)>> = adapter
            .storage_language_keys()
            .into_iter()
            .map(|(lang, _)| (lang, Vec::new()))
            .collect();
        for file in files {
            let Some(blob_oid) = snapshot.validated_oid_for_path(file) else {
                continue;
            };
            let Some(row) = Self::path_symbol_row(adapter, file, blob_oid) else {
                continue;
            };
            rows_by_language
                .entry(adapter.storage_language_key_for_file(file))
                .or_default()
                .push((file.clone(), row));
        }
        let mut dirty = HashMap::default();
        for (lang, entries) in rows_by_language {
            let rows = entries
                .iter()
                .map(|(_, row)| row.clone())
                .collect::<Vec<_>>();
            let mut persisted = false;
            for attempt in 0..=STORE_WRITE_IMMEDIATE_RETRIES {
                if store_context
                    .store
                    .sync_path_symbol_units(&lang, store_context.generations[&lang], &rows)
                    .is_ok()
                {
                    persisted = true;
                    break;
                }
                if attempt < STORE_WRITE_IMMEDIATE_RETRIES {
                    std::thread::sleep(Duration::from_millis(10 * (attempt + 1) as u64));
                }
            }
            if !persisted {
                dirty.extend(
                    entries
                        .into_iter()
                        .map(|(file, row)| (file, (lang.clone(), row))),
                );
            }
        }
        dirty
    }

    fn refresh_path_symbol_units(
        adapter: &A,
        files: &BTreeSet<ProjectFile>,
        store_context: &AnalyzerStoreContext,
        dirty: &mut HashMap<ProjectFile, (String, PathSymbolRow)>,
    ) {
        if !adapter.has_path_synthetic_module_units() {
            return;
        }

        let storage_languages = adapter
            .storage_language_keys()
            .into_iter()
            .map(|(lang, _)| lang)
            .collect::<Vec<_>>();
        let generations = storage_languages
            .iter()
            .map(|lang| (lang.clone(), store_context.generations[lang]))
            .collect();
        let snapshot = store_context.live_paths.snapshot();
        for file in files {
            dirty.remove(file);
            let rel_path = crate::path_utils::rel_path_string(file);
            let replacement = snapshot
                .validated_oid_for_path(file)
                .and_then(|blob_oid| Self::path_symbol_row(adapter, file, blob_oid))
                .map(|row| (adapter.storage_language_key_for_file(file), row));
            let replacement_ref = replacement.as_ref().map(|(lang, row)| (lang.as_str(), row));
            let mut persisted = false;
            for attempt in 0..=STORE_WRITE_IMMEDIATE_RETRIES {
                if store_context
                    .store
                    .replace_path_symbol_unit(
                        &storage_languages,
                        &generations,
                        &rel_path,
                        replacement_ref,
                    )
                    .is_ok()
                {
                    persisted = true;
                    break;
                }
                if attempt < STORE_WRITE_IMMEDIATE_RETRIES {
                    std::thread::sleep(Duration::from_millis(10 * (attempt + 1) as u64));
                }
            }
            if !persisted && let Some((lang, row)) = replacement {
                dirty.insert(file.clone(), (lang, row));
            }
        }
    }

    fn reconcile_file_states(
        project: &dyn Project,
        adapter: &A,
        config: &AnalyzerConfig,
        store_context: &AnalyzerStoreContext,
        input: ReconcileFileStates,
    ) -> AnalyzerRuntimeState {
        let ReconcileFileStates {
            files,
            replace_live_paths,
            progress,
            mut dirty_file_states,
            dirty_path_symbol_rows,
        } = input;
        let mut fresh_parse_errors = HashMap::default();
        let mut seeded_file_states = Vec::new();
        let mut persistence_stats = PersistBatchStats::default();
        let oid_plan =
            Self::resolve_live_oids(project, &files, config, store_context, replace_live_paths);
        match oid_plan {
            Ok(file_oids) => {
                let all_blob_keys: Vec<_> = files
                    .iter()
                    .filter_map(|file| {
                        file_oids
                            .get(file)
                            .map(|oid| (*oid, adapter.storage_language_key_for_file(file)))
                    })
                    .collect();
                let missing = match store_context.store.missing_parsed_blob_keys_at_generations(
                    &all_blob_keys,
                    store_context.generations.as_ref(),
                ) {
                    Ok(missing) => missing,
                    Err(_) => {
                        let mut seen = HashSet::default();
                        all_blob_keys
                            .into_iter()
                            .filter(|key| seen.insert(key.clone()))
                            .collect()
                    }
                };
                let missing_blob_keys: HashSet<(Oid, String)> = missing.iter().cloned().collect();

                if let Some(progress) = progress.as_ref() {
                    progress(BuildProgressEvent::new(
                        adapter.language(),
                        BuildProgressPhase::Reconcile,
                        files.len().saturating_sub(missing_blob_keys.len()),
                        files.len(),
                        None,
                    ));
                }

                let mut representative_by_blob_key = HashMap::default();
                for file in &files {
                    let Some(oid) = file_oids.get(file).copied() else {
                        continue;
                    };
                    let storage_key = adapter.storage_language_key_for_file(file);
                    if missing_blob_keys.contains(&(oid, storage_key.clone())) {
                        representative_by_blob_key
                            .entry((oid, storage_key))
                            .or_insert_with(|| file.clone());
                    }
                }
                let parse_targets: Vec<_> = missing
                    .iter()
                    .map(|(oid, storage_key)| {
                        let file = representative_by_blob_key
                            .get(&(*oid, storage_key.clone()))
                            .expect("every missing blob key must have a representative")
                            .clone();
                        let generation = store_context.generations[storage_key];
                        (file, *oid, storage_key.clone(), generation)
                    })
                    .collect();
                let mut representative_blob_outcomes = HashMap::default();
                let mut parsed_files = HashSet::default();
                persistence_stats = Self::analyze_prepare_and_persist_files(
                    adapter,
                    project,
                    config,
                    parse_targets,
                    progress.clone(),
                    store_context,
                    |file, outcome| {
                        let Some(oid) = file_oids.get(&file).copied() else {
                            return;
                        };
                        let storage_key = adapter.storage_language_key_for_file(&file);
                        match outcome {
                            Some((state, error)) => {
                                let blob_outcome = if error.is_some() {
                                    RepresentativeBlobOutcome::Dirty
                                } else {
                                    RepresentativeBlobOutcome::Persisted
                                };
                                representative_blob_outcomes
                                    .insert((oid, storage_key.clone()), blob_outcome);
                                let key = Self::transient_cache_key(oid, &file);
                                match error {
                                    Some(error) => {
                                        let terminal_stale = error.is_stale_generation();
                                        dirty_file_states.insert(
                                            key.clone(),
                                            Self::dirty_file_state(
                                                Arc::clone(&state),
                                                store_context.generations[&storage_key],
                                                STORE_WRITE_IMMEDIATE_RETRIES + 1,
                                                error.to_string(),
                                                terminal_stale,
                                            ),
                                        );
                                    }
                                    None => {
                                        dirty_file_states.remove(&key);
                                    }
                                }
                                if let Some(errors) = state.parse_errors.clone() {
                                    fresh_parse_errors.insert(file.clone(), errors);
                                }
                                if seeded_file_states.len() < TRANSIENT_FILE_STATE_CACHE_CAPACITY {
                                    seeded_file_states.push((key, Arc::clone(&state)));
                                }
                                parsed_files.insert(file);
                            }
                            None => {
                                representative_blob_outcomes.insert(
                                    (oid, storage_key),
                                    RepresentativeBlobOutcome::Unparseable,
                                );
                            }
                        }
                    },
                );

                let mut hydrate_misses = Vec::new();
                for file in &files {
                    if parsed_files.contains(file) {
                        continue;
                    }
                    let Some(oid) = file_oids.get(file).copied() else {
                        continue;
                    };
                    let storage_key = adapter.storage_language_key_for_file(file);
                    let blob_key = (oid, storage_key);
                    if !missing_blob_keys.contains(&blob_key) {
                        continue;
                    }
                    match representative_blob_outcomes
                        .get(&blob_key)
                        .expect("every missing blob key must have a representative outcome")
                    {
                        RepresentativeBlobOutcome::Persisted
                        | RepresentativeBlobOutcome::Unparseable => {}
                        RepresentativeBlobOutcome::Dirty => hydrate_misses.push(file.clone()),
                    }
                }

                for (file, state) in
                    Self::analyze_files(adapter, project, config, hydrate_misses, progress)
                {
                    let Some(state) = state else {
                        continue;
                    };
                    let mut seed_key = None;
                    if let Some(oid) = file_oids.get(&file).copied() {
                        let storage_key = adapter.storage_language_key_for_file(&file);
                        let generation = store_context.generations[&storage_key];
                        Self::persist_or_mark_dirty(
                            &mut dirty_file_states,
                            store_context,
                            adapter,
                            &file,
                            oid,
                            &storage_key,
                            generation,
                            &state,
                        );
                        seed_key = Some(Self::transient_cache_key(oid, &file));
                    }
                    if let Some(errors) = state.parse_errors.clone() {
                        fresh_parse_errors.insert(file.clone(), errors);
                    }
                    if let Some(key) = seed_key
                        && seeded_file_states.len() < TRANSIENT_FILE_STATE_CACHE_CAPACITY
                    {
                        seeded_file_states.push((key, Arc::new(state)));
                    }
                }
            }
            Err(_) => {
                for (file, state) in Self::analyze_files(adapter, project, config, files, progress)
                {
                    let Some(state) = state else {
                        continue;
                    };
                    let seed_key = if let Ok(source) = project.read_source(&file)
                        && let Ok(oid) = Oid::hash_object(ObjectType::Blob, source.as_bytes())
                    {
                        let storage_key = adapter.storage_language_key_for_file(&file);
                        let generation = store_context.generations[&storage_key];
                        Self::persist_or_mark_dirty(
                            &mut dirty_file_states,
                            store_context,
                            adapter,
                            &file,
                            oid,
                            &storage_key,
                            generation,
                            &state,
                        );
                        Some(Self::transient_cache_key(oid, &file))
                    } else {
                        None
                    };
                    if let Some(errors) = state.parse_errors.clone() {
                        fresh_parse_errors.insert(file.clone(), errors);
                    }
                    if let Some(key) = seed_key
                        && seeded_file_states.len() < TRANSIENT_FILE_STATE_CACHE_CAPACITY
                    {
                        seeded_file_states.push((key, Arc::new(state)));
                    }
                }
            }
        }

        let mut state = AnalyzerRuntimeState::new(
            fresh_parse_errors,
            dirty_file_states,
            dirty_path_symbol_rows,
            seeded_file_states,
        );
        state.persistence_stats = persistence_stats;
        state
    }

    fn source_snapshot_file_state(&self, file: &ProjectFile) -> Option<Arc<FileState>> {
        let oid = self.resolve_live_oid_for_file(file)?;
        let key = Self::transient_cache_key(oid, file);
        self.source_snapshot_file_states
            .lock()
            .expect("source snapshot file-state cache mutex poisoned")
            .get(&key)
    }

    /// The retained source text of an analyzed file. Structural search
    /// re-parses from this instead of touching disk.
    pub(crate) fn file_source(&self, file: &ProjectFile) -> Option<String> {
        self.source_snapshot_file_state(file)
            .or_else(|| self.fetch_file_state(file))
            .map(|state| state.source.clone())
            .or_else(|| self.project.read_source(file).ok())
    }

    fn transient_cache_key(oid: Oid, file: &ProjectFile) -> FileStateCacheKey {
        FileStateCacheKey {
            oid,
            rel_path: file.rel_path().to_path_buf(),
        }
    }

    fn dirty_retry_delay(attempts: usize) -> Duration {
        let exponent = attempts.saturating_sub(1).min(7) as u32;
        let factor = 1u32 << exponent;
        STORE_WRITE_RETRY_BASE_DELAY
            .saturating_mul(factor)
            .min(STORE_WRITE_RETRY_MAX_DELAY)
    }

    fn dirty_file_state(
        state: Arc<FileState>,
        generation: GenerationId,
        attempts: usize,
        last_error: String,
        terminal_stale: bool,
    ) -> DirtyFileState {
        DirtyFileState {
            state,
            generation,
            attempts,
            next_retry_at: Instant::now() + Self::dirty_retry_delay(attempts),
            terminal_stale,
            _last_error: last_error,
        }
    }

    fn write_parsed_blob_with_retries(
        store_context: &AnalyzerStoreContext,
        adapter: &A,
        oid: Oid,
        storage_key: &str,
        generation: GenerationId,
        state: &FileState,
    ) -> std::result::Result<usize, StoreError> {
        let mut last_error = None;
        for attempt in 1..=STORE_WRITE_IMMEDIATE_RETRIES + 1 {
            match store_context.store.write_parsed_blob_at_generation(
                oid,
                storage_key,
                generation,
                adapter,
                state,
            ) {
                Ok(()) => return Ok(attempt),
                Err(err) => {
                    let stale = err.is_stale_generation();
                    last_error = Some(err);
                    if stale {
                        break;
                    }
                    if attempt <= STORE_WRITE_IMMEDIATE_RETRIES {
                        std::thread::sleep(Duration::from_millis(10 * attempt as u64));
                    }
                }
            }
        }
        Err(last_error.expect("failed store write must retain its error"))
    }

    #[allow(clippy::too_many_arguments)]
    fn persist_or_mark_dirty(
        dirty_file_states: &mut HashMap<FileStateCacheKey, DirtyFileState>,
        store_context: &AnalyzerStoreContext,
        adapter: &A,
        file: &ProjectFile,
        oid: Oid,
        storage_key: &str,
        generation: GenerationId,
        state: &FileState,
    ) {
        let key = Self::transient_cache_key(oid, file);
        match Self::write_parsed_blob_with_retries(
            store_context,
            adapter,
            oid,
            storage_key,
            generation,
            state,
        ) {
            Ok(_) => {
                dirty_file_states.remove(&key);
            }
            Err(err) => {
                let terminal_stale = err.is_stale_generation();
                dirty_file_states.insert(
                    key,
                    Self::dirty_file_state(
                        Arc::new(state.clone()),
                        generation,
                        STORE_WRITE_IMMEDIATE_RETRIES + 1,
                        err.to_string(),
                        terminal_stale,
                    ),
                );
            }
        }
    }

    fn remove_dirty_for_file(
        dirty_file_states: &mut HashMap<FileStateCacheKey, DirtyFileState>,
        file: &ProjectFile,
    ) {
        let rel_path = file.rel_path();
        dirty_file_states.retain(|key, _| key.rel_path != rel_path);
    }

    fn retry_dirty_file_state(
        &self,
        key: &FileStateCacheKey,
        storage_key: &str,
    ) -> Option<Arc<FileState>> {
        let (state, generation) = {
            let dirty_file_states = self
                .state
                .dirty_file_states
                .lock()
                .expect("dirty file-state mutex poisoned");
            let dirty = dirty_file_states.get(key)?;
            if dirty.terminal_stale || Instant::now() < dirty.next_retry_at {
                return Some(Arc::clone(&dirty.state));
            }
            (Arc::clone(&dirty.state), dirty.generation)
        };

        match self.store_context.store.write_parsed_blob_at_generation(
            key.oid,
            storage_key,
            generation,
            self.adapter.as_ref(),
            &state,
        ) {
            Ok(()) => {
                self.state
                    .dirty_file_states
                    .lock()
                    .expect("dirty file-state mutex poisoned")
                    .remove(key);
                self.transient_file_states
                    .lock()
                    .expect("transient file-state cache mutex poisoned")
                    .insert(key.clone(), Arc::clone(&state));
                Some(state)
            }
            Err(err) => {
                self.record_store_error(
                    err.clone().context("retrying a deferred parsed-blob write"),
                );
                let mut dirty_file_states = self
                    .state
                    .dirty_file_states
                    .lock()
                    .expect("dirty file-state mutex poisoned");
                if let Some(dirty) = dirty_file_states.get_mut(key) {
                    if err.is_stale_generation() {
                        dirty.terminal_stale = true;
                    }
                    dirty.attempts = dirty.attempts.saturating_add(1);
                    dirty.next_retry_at = Instant::now() + Self::dirty_retry_delay(dirty.attempts);
                    dirty._last_error = err.to_string();
                    return Some(Arc::clone(&dirty.state));
                }
                Some(state)
            }
        }
    }

    fn storage_language_keys_for_queries(&self) -> Vec<String> {
        self.adapter
            .storage_language_keys()
            .into_iter()
            .map(|(key, _)| key)
            .collect()
    }

    pub(crate) fn fetch_file_state(&self, file: &ProjectFile) -> Option<Arc<FileState>> {
        let oid = self.resolve_live_oid_for_file(file)?;
        let key = Self::transient_cache_key(oid, file);
        self.fetch_file_state_for_key(file, &key)
    }

    fn fetch_file_state_for_key(
        &self,
        file: &ProjectFile,
        key: &FileStateCacheKey,
    ) -> Option<Arc<FileState>> {
        self.fetch_file_state_for_key_with_source(file, key, None)
    }

    fn fetch_file_state_for_key_with_source(
        &self,
        file: &ProjectFile,
        key: &FileStateCacheKey,
        exact_source: Option<&str>,
    ) -> Option<Arc<FileState>> {
        let storage_key = self.adapter.storage_language_key_for_file(file);
        if let Some(state) = self.retry_dirty_file_state(key, &storage_key) {
            return Some(state);
        }
        if let Some(state) = self
            .query_read_cache
            .lock()
            .expect("query read cache mutex poisoned")
            .file_state(key)
        {
            return Some(state);
        }
        if let Some(state) = self
            .transient_file_states
            .lock()
            .expect("transient file-state cache mutex poisoned")
            .get(key)
        {
            let mut query_cache = self
                .query_read_cache
                .lock()
                .expect("query read cache mutex poisoned");
            if query_cache.is_active() {
                query_cache.retain_file_state(key.clone(), Arc::clone(&state));
            }
            return Some(state);
        }

        self.full_hydration_count.fetch_add(1, Ordering::Relaxed);
        let source = match exact_source {
            Some(source) => source.to_owned(),
            None => self.source_for_oid(file, key.oid)?,
        };
        let mut state = match self
            .store_query_or_record(
                self.store_context.store.hydrate_file_state_with_source(
                    key.oid,
                    &storage_key,
                    self.store_context.generations[&storage_key],
                    self.adapter.as_ref(),
                    file,
                    &source,
                ),
                format!("hydrating file state for `{file}`"),
            )
            .flatten()
        {
            Some(state) => state,
            None => self.parse_and_store_transient(file, key.oid, source.clone())?,
        };
        state.source = source;
        let state = Arc::new(state);
        self.transient_file_states
            .lock()
            .expect("transient file-state cache mutex poisoned")
            .insert(key.clone(), Arc::clone(&state));
        let mut query_cache = self
            .query_read_cache
            .lock()
            .expect("query read cache mutex poisoned");
        if query_cache.is_active() {
            query_cache.retain_file_state(key.clone(), Arc::clone(&state));
        }
        Some(state)
    }

    pub(crate) fn prepared_syntax(&self, file: &ProjectFile) -> Option<Arc<PreparedSyntaxTree>> {
        self.prepared_syntax_with_limit(file, None).ok().flatten()
    }

    /// Prepare syntax from one atomically captured project source snapshot,
    /// refusing snapshots larger than `max_source_bytes` before parsing.
    pub(crate) fn prepared_syntax_limited(
        &self,
        file: &ProjectFile,
        max_source_bytes: usize,
    ) -> Result<Option<Arc<PreparedSyntaxTree>>, PreparedSyntaxLimitExceeded> {
        self.prepared_syntax_with_limit(file, Some(max_source_bytes))
    }

    fn prepared_syntax_with_limit(
        &self,
        file: &ProjectFile,
        max_source_bytes: Option<usize>,
    ) -> Result<Option<Arc<PreparedSyntaxTree>>, PreparedSyntaxLimitExceeded> {
        let Some(resolved) = self.resolve_prepared_source(file, max_source_bytes)? else {
            return Ok(None);
        };
        let key = Self::transient_cache_key(resolved.oid, file);
        let (origin, overlay_revision) = match resolved.snapshot.origin() {
            ProjectSourceOrigin::Disk => (PreparedSourceOrigin::Disk, None),
            ProjectSourceOrigin::Overlay(revision) => {
                (PreparedSourceOrigin::Overlay, Some(revision))
            }
        };
        let prepared_key = PreparedSyntaxCacheKey {
            file_state: key.clone(),
            origin,
            overlay_revision,
        };
        let cell = self
            .query_read_cache
            .lock()
            .expect("query read cache mutex poisoned")
            .prepared_syntax_cell(prepared_key);
        let Some(cell) = cell else {
            return Ok(self.prepare_syntax_for_key(
                file,
                &key,
                origin,
                overlay_revision,
                resolved.snapshot.source(),
            ));
        };
        Ok(cell
            .get_or_init(|| {
                #[cfg(test)]
                {
                    let mut counts = self
                        .prepared_syntax_parse_counts
                        .lock()
                        .expect("prepared syntax parse count mutex poisoned");
                    *counts.entry(key.clone()).or_default() += 1;
                }
                self.prepare_syntax_for_key(
                    file,
                    &key,
                    origin,
                    overlay_revision,
                    resolved.snapshot.source(),
                )
            })
            .clone())
    }

    fn prepare_syntax_for_key(
        &self,
        file: &ProjectFile,
        key: &FileStateCacheKey,
        origin: PreparedSourceOrigin,
        overlay_revision: Option<OverlayRevision>,
        exact_source: &str,
    ) -> Option<Arc<PreparedSyntaxTree>> {
        let file_state =
            self.fetch_file_state_for_key_with_source(file, key, Some(exact_source))?;
        let mut parser = Parser::new();
        parser
            .set_language(&self.adapter.parser_language_for_file(file))
            .ok()?;
        let tree = parser.parse(file_state.source.as_str(), None)?;
        let line_starts = compute_line_starts(&file_state.source);
        Some(Arc::new(PreparedSyntaxTree {
            file_state,
            tree,
            line_starts,
            dialect: LanguageDialect::for_path(self.adapter.language(), file.rel_path()),
            origin,
            overlay_revision,
        }))
    }

    #[cfg(test)]
    pub(crate) fn prepared_syntax_parse_count_for_test(&self, file: &ProjectFile) -> usize {
        let Some(oid) = self.resolve_live_oid_for_file(file) else {
            return 0;
        };
        let key = Self::transient_cache_key(oid, file);
        self.prepared_syntax_parse_counts
            .lock()
            .expect("prepared syntax parse count mutex poisoned")
            .get(&key)
            .copied()
            .unwrap_or_default()
    }

    pub(crate) fn bulk_file_states(
        &self,
        files: impl IntoIterator<Item = ProjectFile>,
        source_mode: BulkFileStateSource,
    ) -> HashMap<ProjectFile, FileState> {
        let mut entries = Vec::new();
        let mut seen = HashSet::default();
        for file in files {
            if crate::analyzer::common::language_for_file(&file) != self.adapter.language() {
                continue;
            }
            if !seen.insert(file.clone()) {
                continue;
            }
            let Some(oid) = self.resolve_live_oid_for_file(&file) else {
                continue;
            };
            let storage_key = self.adapter.storage_language_key_for_file(&file);
            entries.push((file, oid, storage_key));
        }
        if entries.is_empty() {
            return HashMap::default();
        }

        let mut out = HashMap::default();
        let mut clean_entries = Vec::new();
        for (file, oid, storage_key) in entries {
            let key = Self::transient_cache_key(oid, &file);
            if let Some(state) = self.retry_dirty_file_state(&key, &storage_key) {
                out.insert(file, state.as_ref().clone());
            } else {
                clean_entries.push((file, oid, storage_key));
            }
        }
        let entries = clean_entries;
        if entries.is_empty() {
            return out;
        }

        let mut source_by_file = HashMap::default();
        if source_mode == BulkFileStateSource::Include {
            for (file, oid, _) in &entries {
                if let Some(source) = self.source_for_oid(file, *oid) {
                    source_by_file.insert(file.clone(), source);
                }
            }
        }

        let mut states = self
            .store_query_or_record(
                self.store_context.store.hydrate_file_states_by_key(
                    &entries,
                    self.store_context.generations.as_ref(),
                    self.adapter.as_ref(),
                    &source_by_file,
                ),
                "hydrating file states",
            )
            .unwrap_or_default();
        self.bulk_hydration_count
            .fetch_add(states.len(), Ordering::Relaxed);
        for (file, oid, _) in entries {
            if states.contains_key(&file) {
                continue;
            }
            if let Some(source) = self.source_for_oid(&file, oid)
                && let Some(state) = self.parse_and_store_transient(&file, oid, source)
            {
                states.insert(file, state);
            }
        }
        out.extend(states);
        out
    }

    pub(crate) fn bulk_import_infos(
        &self,
        files: impl IntoIterator<Item = ProjectFile>,
    ) -> HashMap<ProjectFile, Vec<ImportInfo>> {
        self.bulk_import_facts(files)
            .into_iter()
            .map(|(file, facts)| (file, facts.imports))
            .collect()
    }

    pub(crate) fn bulk_import_facts(
        &self,
        files: impl IntoIterator<Item = ProjectFile>,
    ) -> HashMap<ProjectFile, ImportFileFacts> {
        let mut entries = Vec::new();
        let mut seen = HashSet::default();
        for file in files {
            if crate::analyzer::common::language_for_file(&file) != self.adapter.language() {
                continue;
            }
            if !seen.insert(file.clone()) {
                continue;
            }
            let Some(oid) = self.resolve_live_oid_for_file(&file) else {
                continue;
            };
            let storage_key = self.adapter.storage_language_key_for_file(&file);
            entries.push((file, oid, storage_key));
        }
        if entries.is_empty() {
            return HashMap::default();
        }
        let mut out = HashMap::default();
        let mut clean_entries = Vec::new();
        for (file, oid, storage_key) in entries {
            let key = Self::transient_cache_key(oid, &file);
            if let Some(state) = self.retry_dirty_file_state(&key, &storage_key) {
                out.insert(
                    file,
                    ImportFileFacts {
                        package_name: state.package_name.clone(),
                        imports: state.imports.clone(),
                    },
                );
            } else {
                clean_entries.push((file, oid, storage_key));
            }
        }
        let entries = clean_entries;
        if entries.is_empty() {
            return out;
        }
        let mut facts: HashMap<ProjectFile, ImportFileFacts> = self
            .store_query_or_record(
                self.store_context.store.hydrate_import_facts_by_key(
                    &entries,
                    self.store_context.generations.as_ref(),
                    self.adapter.as_ref(),
                ),
                "hydrating import facts",
            )
            .unwrap_or_default()
            .into_iter()
            .map(|(file, facts)| {
                (
                    file,
                    ImportFileFacts {
                        package_name: facts.package_name,
                        imports: facts.imports,
                    },
                )
            })
            .collect();
        self.bulk_hydration_count
            .fetch_add(facts.len(), Ordering::Relaxed);
        for (file, oid, _) in entries {
            if facts.contains_key(&file) {
                continue;
            }
            if let Some(source) = self.source_for_oid(&file, oid)
                && let Some(state) = self.parse_and_store_transient(&file, oid, source)
            {
                facts.insert(
                    file,
                    ImportFileFacts {
                        package_name: state.package_name,
                        imports: state.imports,
                    },
                );
            }
        }
        out.extend(facts);
        out
    }

    fn resolve_prepared_source(
        &self,
        file: &ProjectFile,
        max_source_bytes: Option<usize>,
    ) -> Result<Option<ResolvedPreparedSource>, PreparedSyntaxLimitExceeded> {
        {
            let cache = self
                .query_read_cache
                .lock()
                .expect("query read cache mutex poisoned");
            if cache.is_active()
                && let Some(cached) = cache.prepared_source(file)
            {
                if let (Some(source), Some(max_source_bytes)) = (&cached, max_source_bytes)
                    && source.snapshot.source().len() > max_source_bytes
                {
                    return Err(PreparedSyntaxLimitExceeded {
                        minimum_source_bytes: source.snapshot.source().len(),
                    });
                }
                return Ok(cached);
            }
        }

        let snapshot = match max_source_bytes {
            Some(max_source_bytes) => {
                match self
                    .project
                    .read_source_snapshot_limited(file, max_source_bytes)
                {
                    Ok(Some(snapshot)) => Some(snapshot),
                    Ok(None) => {
                        return Err(PreparedSyntaxLimitExceeded {
                            minimum_source_bytes: max_source_bytes.saturating_add(1),
                        });
                    }
                    Err(_) => None,
                }
            }
            None => self.project.read_source_snapshot(file).ok(),
        };
        let resolved = snapshot.and_then(|snapshot| {
            Oid::hash_object(ObjectType::Blob, snapshot.source().as_bytes())
                .ok()
                .map(|oid| ResolvedPreparedSource { oid, snapshot })
        });

        let mut cache = self
            .query_read_cache
            .lock()
            .expect("query read cache mutex poisoned");
        if cache.is_active() {
            cache.retain_prepared_source(file.clone(), resolved.clone());
        }
        Ok(resolved)
    }

    fn resolve_live_source_for_file(&self, file: &ProjectFile) -> Option<ResolvedLiveSource> {
        {
            let cache = self
                .query_read_cache
                .lock()
                .expect("query read cache mutex poisoned");
            if cache.is_active()
                && let Some(source) = cache.live_sources.get(file).copied()
            {
                return source;
            }
        }
        #[cfg(test)]
        if !self.project.has_overlay(file) {
            *self
                .live_oid_validation_counts
                .lock()
                .expect("live OID validation count mutex poisoned")
                .entry(file.clone())
                .or_default() += 1;
        }
        let source = if self.project.has_overlay(file) {
            let source = self.project.read_source(file).ok()?;
            Oid::hash_object(ObjectType::Blob, source.as_bytes())
                .ok()
                .map(|oid| ResolvedLiveSource { oid })
        } else if let Some(oid) = self
            .store_context
            .live_paths
            .snapshot()
            .validated_oid_for_path(file)
        {
            Some(ResolvedLiveSource { oid })
        } else if let Some(liveness) = self.store_context.liveness.as_ref()
            && let Ok(Some(oid)) = liveness.oid_for_path(file)
        {
            Some(ResolvedLiveSource { oid })
        } else if file.exists()
            && let Ok(bytes) = std::fs::read(file.abs_path())
            && let Ok(oid) = Oid::hash_object(ObjectType::Blob, &bytes)
        {
            Some(ResolvedLiveSource { oid })
        } else {
            self.git_index_oid_for_file(file)
                .map(|oid| ResolvedLiveSource { oid })
        };
        let mut cache = self
            .query_read_cache
            .lock()
            .expect("query read cache mutex poisoned");
        if cache.is_active() {
            cache.live_sources.insert(file.clone(), source);
        }
        source
    }

    fn resolve_live_oid_for_file(&self, file: &ProjectFile) -> Option<Oid> {
        self.resolve_live_source_for_file(file)
            .map(|source| source.oid)
    }

    #[cfg(test)]
    pub(crate) fn reset_live_oid_validation_counts_for_test(&self) {
        self.live_oid_validation_counts
            .lock()
            .expect("live OID validation count mutex poisoned")
            .clear();
    }

    #[cfg(test)]
    pub(crate) fn live_oid_validation_count_for_test(&self, file: &ProjectFile) -> usize {
        self.live_oid_validation_counts
            .lock()
            .expect("live OID validation count mutex poisoned")
            .get(file)
            .copied()
            .unwrap_or(0)
    }

    fn git_index_oid_for_file(&self, file: &ProjectFile) -> Option<Oid> {
        let repo = gitblob::discover(self.project.root())?;
        let index = repo.index().ok()?;
        index.get_path(file.rel_path(), 0).map(|entry| entry.id)
    }

    fn source_for_oid(&self, file: &ProjectFile, oid: Oid) -> Option<String> {
        if let Ok(source) = self.project.read_source(file)
            && Oid::hash_object(ObjectType::Blob, source.as_bytes()).ok() == Some(oid)
        {
            return Some(source);
        }
        if let Some(source) = self.source_from_git_blob(oid) {
            return Some(source);
        }
        None
    }

    fn source_from_git_blob(&self, oid: Oid) -> Option<String> {
        let repo = gitblob::discover(self.project.root())?;
        let bytes = gitblob::read_blob(&repo, &oid.to_string()).ok()?;
        String::from_utf8(bytes).ok()
    }

    fn parse_and_store_transient(
        &self,
        file: &ProjectFile,
        oid: Oid,
        source: String,
    ) -> Option<FileState> {
        let storage_key = self.adapter.storage_language_key_for_file(file);
        let generation = self.store_context.generations[&storage_key];
        let mut parser = Self::build_parser(self.adapter.parser_language());
        let state = Self::analyze_source(&mut parser, self.adapter.as_ref(), file, source)?;
        let key = Self::transient_cache_key(oid, file);
        match Self::write_parsed_blob_with_retries(
            &self.store_context,
            self.adapter.as_ref(),
            oid,
            &storage_key,
            generation,
            &state,
        ) {
            Ok(_) => {
                self.state
                    .dirty_file_states
                    .lock()
                    .expect("dirty file-state mutex poisoned")
                    .remove(&key);
            }
            Err(err) => {
                let terminal_stale = err.is_stale_generation();
                self.state
                    .dirty_file_states
                    .lock()
                    .expect("dirty file-state mutex poisoned")
                    .insert(
                        key,
                        Self::dirty_file_state(
                            Arc::new(state.clone()),
                            generation,
                            STORE_WRITE_IMMEDIATE_RETRIES + 1,
                            err.to_string(),
                            terminal_stale,
                        ),
                    );
            }
        }
        let live_entry = if self.project.has_overlay(file) || self.store_context.liveness.is_none()
        {
            LivePathEntry::overlay(file.clone(), oid)
        } else {
            LivePathEntry::filesystem(file.clone(), oid)
        };
        self.store_context.live_paths.refresh([live_entry]);
        Some(state)
    }

    fn live_snapshot(&self) -> Arc<LiveSnapshot> {
        self.store_context.live_paths.snapshot()
    }

    fn analyzed_live_files(&self) -> Vec<ProjectFile> {
        if let Some(files) = self
            .query_read_cache
            .lock()
            .expect("query read cache mutex poisoned")
            .analyzed_live_files()
        {
            return files;
        }
        let snapshot = self.live_snapshot();
        let mut files = Vec::new();
        let mut persisted_candidates = Vec::new();
        for file in snapshot.all_paths() {
            let Some(project_file) = self.rebase_live_file_to_project_root(file) else {
                continue;
            };
            if crate::analyzer::common::language_for_file(&project_file) != self.adapter.language()
            {
                continue;
            }
            let Some(oid) = snapshot.validated_oid_for_path(file) else {
                continue;
            };
            let storage_key = self.adapter.storage_language_key_for_file(&project_file);
            let key = Self::transient_cache_key(oid, &project_file);
            if self.retry_dirty_file_state(&key, &storage_key).is_some() {
                files.push(project_file);
                continue;
            }
            persisted_candidates.push((project_file, oid, storage_key));
        }
        let keys = persisted_candidates
            .iter()
            .map(|(_, oid, storage_key)| (*oid, storage_key.clone()))
            .collect::<Vec<_>>();
        let present = self
            .store_query_or_record(
                self.store_context.store.parsed_blob_keys_at_generations(
                    &keys,
                    self.store_context.generations.as_ref(),
                ),
                "checking analyzed live files",
            )
            .unwrap_or_default();
        for (project_file, oid, storage_key) in persisted_candidates {
            if present.contains(&(oid, storage_key)) {
                files.push(project_file);
            }
        }
        files.sort();
        files.dedup();
        self.query_read_cache
            .lock()
            .expect("query read cache mutex poisoned")
            .retain_analyzed_live_files(files.clone());
        files
    }

    fn resolve_candidate_rows(
        &self,
        rows: Vec<crate::analyzer::store::CandidateRow>,
    ) -> Vec<CodeUnit> {
        QueryResolver::from_snapshot(
            self.adapter.as_ref(),
            self.project.root(),
            self.live_snapshot(),
        )
        .resolve_rows(rows)
    }

    fn resolve_definition_order_candidate_rows(
        &self,
        rows: Vec<crate::analyzer::store::DefinitionOrderCandidateRow>,
    ) -> Vec<DefinitionSortCandidate> {
        QueryResolver::from_snapshot(
            self.adapter.as_ref(),
            self.project.root(),
            self.live_snapshot(),
        )
        .resolve_rows_with_payload(
            rows.into_iter()
                .map(|row| (row.candidate, row.first_start_byte)),
        )
        .into_iter()
        .map(|(unit, first_start_byte)| DefinitionSortCandidate {
            unit,
            range_start: DefinitionRangeStart::Persisted(first_start_byte),
        })
        .collect()
    }

    fn sql_path_symbol_units(
        &self,
        fq_name: &str,
        normalized: &str,
    ) -> std::result::Result<Vec<CodeUnit>, StoreError> {
        if !self.adapter.has_path_synthetic_module_units() {
            return Ok(Vec::new());
        }

        let rows = self
            .store_context
            .store
            .path_symbol_rows_by_fqn_for_langs(
                &self.storage_language_keys_for_queries(),
                self.store_context.generations.as_ref(),
                fq_name,
                normalized,
            )
            .map_err(|error| error.context("querying path-backed definition candidates"))?;
        let snapshot = self.live_snapshot();
        let mut units = Vec::with_capacity(rows.len());
        for (lang, row) in rows {
            if let Some(unit) = self.live_path_symbol_unit(&lang, &row, &snapshot)
                && (unit.fq_name() == fq_name
                    || self.adapter.normalize_full_name(&unit.fq_name()) == normalized)
            {
                units.push(unit);
            }
        }
        for (lang, row) in self
            .state
            .dirty_path_symbol_rows
            .lock()
            .expect("dirty path-symbol mutex poisoned")
            .values()
        {
            if let Some(unit) = self.live_path_symbol_unit(lang, row, &snapshot)
                && (unit.fq_name() == fq_name
                    || self.adapter.normalize_full_name(&unit.fq_name()) == normalized)
            {
                units.push(unit);
            }
        }
        units.sort_by_cached_key(|unit| self.definition_sort_key_for_unit(unit));
        units.dedup();
        Ok(units)
    }

    fn live_path_symbol_unit(
        &self,
        lang: &str,
        row: &PathSymbolRow,
        snapshot: &LiveSnapshot,
    ) -> Option<CodeUnit> {
        let file = ProjectFile::new(self.project.root().to_path_buf(), &row.rel_path);
        if self.adapter.storage_language_key_for_file(&file) != lang
            || snapshot.validated_oid_for_path(&file) != Some(row.blob_oid)
        {
            return None;
        }
        let unit = self.adapter.path_synthetic_module_unit(&file)?;
        (unit.kind() == row.kind
            && unit.package_name() == row.package_name
            && unit.short_name() == row.short_name
            && unit.fq_name() == row.exact_fqn
            && self.adapter.normalize_full_name(&unit.fq_name()) == row.normalized_fqn)
            .then_some(unit)
    }

    fn rebase_live_file_to_project_root(&self, file: &ProjectFile) -> Option<ProjectFile> {
        crate::analyzer::common::rebase_project_file_to_root(file, self.project.root())
    }

    fn sql_nonpersisted_workspace_declarations_vec_matching(
        &self,
        keep: impl FnMut(&CodeUnit) -> bool,
    ) -> Option<Vec<CodeUnit>> {
        self.store_query_or_record(
            self.try_sql_nonpersisted_workspace_declarations_vec_matching(keep),
            "querying non-persisted workspace declarations",
        )
    }

    fn try_sql_nonpersisted_workspace_declarations_vec_matching(
        &self,
        mut keep: impl FnMut(&CodeUnit) -> bool,
    ) -> std::result::Result<Vec<CodeUnit>, StoreError> {
        if !self.adapter.has_path_synthetic_module_units() {
            return Ok(Vec::new());
        }
        self.workspace_path_scan_count
            .fetch_add(1, Ordering::Relaxed);
        let snapshot = self.live_snapshot();
        let mut candidates = Vec::new();
        let mut candidate_files = Vec::new();
        for file in snapshot.all_paths() {
            let Some(project_file) = self.rebase_live_file_to_project_root(file) else {
                continue;
            };
            if crate::analyzer::common::language_for_file(&project_file) != self.adapter.language()
            {
                continue;
            }
            let Some(module) = self.adapter.path_synthetic_module_unit(&project_file) else {
                continue;
            };
            if !keep(&module) {
                continue;
            }
            let Some(oid) = snapshot.oid_for_path(file) else {
                continue;
            };
            candidate_files.push(file.clone());
            candidates.push((file.clone(), oid, module));
        }

        let stale: HashSet<_> = snapshot
            .validate(candidate_files.iter())
            .into_iter()
            .collect();
        candidates.retain(|(file, _, _)| !stale.contains(file));

        if self.adapter.path_synthetic_module_requires_imports() {
            let mut blob_keys: Vec<_> = candidates
                .iter()
                .map(|(file, oid, _)| {
                    let project_file = self
                        .rebase_live_file_to_project_root(file)
                        .unwrap_or_else(|| file.clone());
                    (
                        *oid,
                        self.adapter.storage_language_key_for_file(&project_file),
                    )
                })
                .collect();
            blob_keys.sort();
            blob_keys.dedup();
            let import_oids = self
                .store_context
                .store
                .blobs_with_structured_imports_by_keys(
                    &blob_keys,
                    self.store_context.generations.as_ref(),
                )?;
            candidates.retain(|(file, oid, _)| {
                let project_file = self
                    .rebase_live_file_to_project_root(file)
                    .unwrap_or_else(|| file.clone());
                self.adapter
                    .include_path_synthetic_module(import_oids.contains(&(
                        *oid,
                        self.adapter.storage_language_key_for_file(&project_file),
                    )))
            });
        }

        let mut declarations: Vec<_> = candidates
            .into_iter()
            .map(|(_, _, module)| module)
            .filter(|unit| !unit.is_file_scope())
            .collect();
        declarations.sort();
        declarations.dedup();
        Ok(declarations)
    }

    fn dirty_file_states_for_queries(&self) -> Vec<FileState> {
        let snapshot = self.live_snapshot();
        let dirty = self.state.dirty_snapshot();
        let mut states = Vec::new();
        for (key, _) in dirty {
            let file = ProjectFile::new(self.project.root().to_path_buf(), key.rel_path.clone());
            if crate::analyzer::common::language_for_file(&file) != self.adapter.language() {
                continue;
            }
            if snapshot.validated_oid_for_path(&file) != Some(key.oid) {
                continue;
            }
            let storage_key = self.adapter.storage_language_key_for_file(&file);
            if let Some(state) = self.retry_dirty_file_state(&key, &storage_key) {
                states.push(state.as_ref().clone());
            }
        }
        states
    }

    fn dirty_units_matching(
        &self,
        include_definition_lookup_units: bool,
        mut keep: impl FnMut(&CodeUnit) -> bool,
    ) -> Vec<CodeUnit> {
        let mut out = Vec::new();
        for state in self.dirty_file_states_for_queries() {
            out.extend(
                state
                    .declarations
                    .into_iter()
                    .filter(|unit| !unit.is_file_scope() && keep(unit)),
            );
            if include_definition_lookup_units {
                out.extend(
                    state
                        .definition_lookup_units
                        .into_iter()
                        .filter(|unit| !unit.is_file_scope() && keep(unit)),
                );
            }
        }
        out
    }

    fn sql_global_usage_definition_index(
        &self,
    ) -> std::result::Result<GlobalUsageDefinitionIndex, StoreError> {
        let _scope = profiling::scope("TreeSitterAnalyzer::sql_global_usage_definition_index");
        if profiling::enabled() {
            profiling::note(format!("language={:?}", self.adapter.language()));
        }
        let blob_keys = {
            let _scope = profiling::scope("global_usage_definition_index::enumerate_live_keys");
            let snapshot = self.live_snapshot();
            let mut blob_keys = Vec::new();
            for file in snapshot.all_paths() {
                let Some(project_file) = self.rebase_live_file_to_project_root(file) else {
                    continue;
                };
                if crate::analyzer::common::language_for_file(&project_file)
                    != self.adapter.language()
                {
                    continue;
                }
                let Some(oid) = snapshot.oid_for_path(file) else {
                    continue;
                };
                blob_keys.push((
                    oid,
                    self.adapter.storage_language_key_for_file(&project_file),
                ));
            }
            blob_keys.sort();
            blob_keys.dedup();
            if profiling::enabled() {
                profiling::note(format!("live_blob_keys={}", blob_keys.len()));
            }
            blob_keys
        };

        let rows = {
            let _scope = profiling::scope("global_usage_definition_index::fetch_persisted_rows");
            let rows = self
                .store_context
                .store
                .definition_lookup_candidate_rows_by_keys(
                    &blob_keys,
                    self.store_context.generations.as_ref(),
                )?;
            if profiling::enabled() {
                profiling::note(format!("persisted_rows={}", rows.len()));
            }
            rows
        };
        let mut units = {
            let _scope = profiling::scope("global_usage_definition_index::resolve_persisted_rows");
            self.resolve_candidate_rows(rows)
        };
        units.retain(|unit| !unit.is_file_scope());
        let dirty_units = {
            let _scope = profiling::scope("global_usage_definition_index::collect_dirty_units");
            self.dirty_units_matching(true, |_| true)
        };
        let nonpersisted_units = {
            let _scope =
                profiling::scope("global_usage_definition_index::collect_nonpersisted_units");
            self.try_sql_nonpersisted_workspace_declarations_vec_matching(|unit| {
                !unit.is_file_scope()
            })?
        };
        if profiling::enabled() {
            profiling::note(format!(
                "resolved_persisted_units={} dirty_units={} nonpersisted_units={}",
                units.len(),
                dirty_units.len(),
                nonpersisted_units.len()
            ));
        }
        units.extend(dirty_units);
        units.extend(nonpersisted_units);
        let _scope = profiling::scope("global_usage_definition_index::build");
        Ok(GlobalUsageDefinitionIndex::from_declarations(
            units.iter(),
            |fqn| self.adapter.normalize_full_name(fqn),
            |unit| self.adapter.simple_type_name(unit),
        ))
    }

    #[doc(hidden)]
    pub fn reset_full_hydration_count_for_test(&self) {
        self.full_hydration_count.store(0, Ordering::Relaxed);
        self.bulk_hydration_count.store(0, Ordering::Relaxed);
    }

    #[doc(hidden)]
    pub fn full_hydration_count_for_test(&self) -> usize {
        self.full_hydration_count.load(Ordering::Relaxed)
    }

    #[doc(hidden)]
    pub fn bulk_hydration_count_for_test(&self) -> usize {
        self.bulk_hydration_count.load(Ordering::Relaxed)
    }

    #[doc(hidden)]
    pub fn reset_enclosing_parent_query_counts_for_test(&self) {
        self.enclosing_code_unit_query_count
            .store(0, Ordering::Relaxed);
        self.sql_definitions_query_count.store(0, Ordering::Relaxed);
    }

    #[doc(hidden)]
    pub fn enclosing_code_unit_query_count_for_test(&self) -> usize {
        self.enclosing_code_unit_query_count.load(Ordering::Relaxed)
    }

    #[doc(hidden)]
    pub fn sql_definitions_query_count_for_test(&self) -> usize {
        self.sql_definitions_query_count.load(Ordering::Relaxed)
    }

    #[doc(hidden)]
    pub fn reset_definition_candidates_query_count_for_test(&self) {
        self.definition_candidates_query_count
            .store(0, Ordering::Relaxed);
    }

    #[doc(hidden)]
    pub fn definition_candidates_query_count_for_test(&self) -> usize {
        self.definition_candidates_query_count
            .load(Ordering::Relaxed)
    }

    #[doc(hidden)]
    pub fn reset_full_declaration_scan_count_for_test(&self) {
        self.full_declaration_scan_count.store(0, Ordering::Relaxed);
    }

    #[doc(hidden)]
    pub fn full_declaration_scan_count_for_test(&self) -> usize {
        self.full_declaration_scan_count.load(Ordering::Relaxed)
    }

    #[doc(hidden)]
    pub fn reset_global_usage_definition_index_build_count_for_test(&self) {
        self.global_usage_definition_index_build_count
            .store(0, Ordering::Relaxed);
    }

    #[doc(hidden)]
    pub fn global_usage_definition_index_build_count_for_test(&self) -> usize {
        self.global_usage_definition_index_build_count
            .load(Ordering::Relaxed)
    }

    #[doc(hidden)]
    pub fn reset_workspace_path_scan_count_for_test(&self) {
        self.workspace_path_scan_count.store(0, Ordering::Relaxed);
    }

    #[doc(hidden)]
    pub fn workspace_path_scan_count_for_test(&self) -> usize {
        self.workspace_path_scan_count.load(Ordering::Relaxed)
    }

    pub(crate) fn forward_definition_fqn(&self, fq_name: &str) -> Vec<CodeUnit> {
        match self.sql_bounded_definitions_vec(fq_name) {
            Ok(definitions) => definitions,
            Err(error) => {
                self.record_store_error(error);
                Vec::new()
            }
        }
    }

    pub(crate) fn forward_path_module_fqn(&self, fq_name: &str) -> Option<Vec<CodeUnit>> {
        let normalized = self.adapter.normalize_full_name(fq_name);
        match self.sql_path_symbol_units(fq_name, &normalized) {
            Ok(units) => Some(units),
            Err(error) => {
                self.record_store_error(error);
                None
            }
        }
    }

    pub(crate) fn forward_file_identifier(
        &self,
        file: &ProjectFile,
        identifier: &str,
    ) -> Vec<CodeUnit> {
        let Some(state) = self.fetch_file_state(file) else {
            return Vec::new();
        };
        let mut matches = state
            .declarations
            .iter()
            .chain(&state.definition_lookup_units)
            .filter(|unit| !unit.is_file_scope() && unit.identifier() == identifier)
            .cloned()
            .collect::<Vec<_>>();
        matches.sort();
        matches.dedup();
        matches
    }

    pub(crate) fn forward_direct_children(&self, owner: &CodeUnit) -> Vec<CodeUnit> {
        <Self as IAnalyzer>::direct_children(self, owner)
    }

    pub(crate) fn forward_package_exists(&self, package: &str) -> bool {
        self.persisted_package_exists(package)
    }

    pub(crate) fn forward_fqn_prefix_exists(&self, prefix: &str) -> bool {
        let nested = format!("{prefix}.");
        let matches = |unit: &CodeUnit| {
            unit.package_name() == prefix
                || unit.package_name().starts_with(&nested)
                || unit.fq_name().starts_with(&nested)
        };
        if self
            .dirty_units_matching(false, matches)
            .into_iter()
            .any(|_| true)
        {
            return true;
        }

        const PAGE_SIZE: usize = 64;
        for lang in self.storage_language_keys_for_queries() {
            let mut after: Option<(String, Oid, i64)> = None;
            loop {
                let Some(rows) = self.store_query_or_record(
                    self.store_context
                        .store
                        .declaration_rows_by_package_prefix_page(
                            &lang,
                            self.store_context.generations[&lang],
                            prefix,
                            after.as_ref().map(|(qualifier, oid, unit_key)| {
                                (qualifier.as_str(), *oid, *unit_key)
                            }),
                            PAGE_SIZE,
                        ),
                    format!("querying declaration package prefix `{prefix}`"),
                ) else {
                    return false;
                };
                let Some(last) = rows.last() else {
                    break;
                };
                let next = (last.content_qualifier.clone(), last.blob_oid, last.unit_key);
                let complete = rows.len() < PAGE_SIZE;
                if self.resolve_candidate_rows(rows).iter().any(matches) {
                    return true;
                }
                if complete {
                    break;
                }
                after = Some(next);
            }
        }
        false
    }

    #[doc(hidden)]
    pub fn write_live_file_to_store_for_test(&self, file: &ProjectFile) -> Option<()> {
        if !file.exists() && !self.project.has_overlay(file) {
            return None;
        }
        let source = self.project.read_source(file).ok()?;
        let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).ok()?;
        let live_entry = if self.project.has_overlay(file) || self.store_context.liveness.is_none()
        {
            LivePathEntry::overlay(file.clone(), oid)
        } else {
            LivePathEntry::filesystem(file.clone(), oid)
        };
        let mut parser = Self::build_parser(self.adapter.parser_language());
        let state = Self::analyze_source(&mut parser, self.adapter.as_ref(), file, source)?;
        let storage_key = self.adapter.storage_language_key_for_file(file);
        self.store_query_or_record(
            self.store_context.store.write_parsed_blob_at_generation(
                oid,
                &storage_key,
                self.store_context.generations[&storage_key],
                self.adapter.as_ref(),
                &state,
            ),
            format!(
                "persisting live analyzer state for {}",
                file.rel_path().display()
            ),
        )?;
        if let Some(liveness) = self.store_context.liveness.as_ref() {
            liveness.refresh_overlay([live_entry.clone()]).ok()?;
        }
        self.store_context.live_paths.refresh([live_entry]);
        Some(())
    }

    fn sql_all_declarations_vec(&self) -> Option<Vec<CodeUnit>> {
        self.full_declaration_scan_count
            .fetch_add(1, Ordering::Relaxed);
        let rows = self.store_query_or_record(
            self.store_context
                .store
                .declaration_candidate_rows_for_langs(
                    &self.storage_language_keys_for_queries(),
                    self.store_context.generations.as_ref(),
                ),
            "scanning all declarations",
        )?;
        let mut units = self.resolve_candidate_rows(rows);
        units.extend(self.dirty_units_matching(false, |_| true));
        units.extend(self.sql_nonpersisted_workspace_declarations_vec_matching(|_| true)?);
        units.retain(|unit| !unit.is_file_scope());
        units.sort();
        units.dedup();
        Some(units)
    }

    fn sql_all_declarations_with_primary_ranges_vec(
        &self,
    ) -> Option<Vec<(CodeUnit, Option<Range>)>> {
        let rows = self.store_query_or_record(
            self.store_context
                .store
                .declaration_candidate_rows_with_primary_ranges_for_langs(
                    &self.storage_language_keys_for_queries(),
                    self.store_context.generations.as_ref(),
                ),
            "scanning declarations with primary ranges",
        )?;
        let resolver = QueryResolver::from_snapshot(
            self.adapter.as_ref(),
            self.project.root(),
            self.live_snapshot(),
        );
        let mut units = resolver.resolve_rows_with_payload(rows);
        for state in self.dirty_file_states_for_queries() {
            units.extend(
                state
                    .declarations
                    .iter()
                    .filter(|unit| !unit.is_file_scope())
                    .cloned()
                    .map(|unit| {
                        let range = state.ranges.get(&unit).and_then(|ranges| {
                            ranges
                                .iter()
                                .copied()
                                .min_by_key(|range| (range.start_line, range.start_byte))
                        });
                        (unit, range)
                    }),
            );
        }
        units.extend(
            self.sql_nonpersisted_workspace_declarations_vec_matching(|_| true)?
                .into_iter()
                .map(|unit| (unit, None)),
        );
        units.retain(|(unit, _)| !unit.is_file_scope());
        units.sort_by(|(left, _), (right, _)| left.cmp(right));
        units.dedup_by(|(left, _), (right, _)| left == right);
        Some(units)
    }

    pub(crate) fn hierarchy_declaration_facts_by_kind(
        &self,
        kind: CodeUnitType,
    ) -> Option<Vec<HierarchyDeclarationFacts>> {
        let rows = self.store_query_or_record(
            self.store_context
                .store
                .declaration_candidate_rows_with_primary_ranges_by_kind_for_langs(
                    &self.storage_language_keys_for_queries(),
                    self.store_context.generations.as_ref(),
                    kind,
                ),
            format!("querying {kind:?} hierarchy declarations"),
        )?;
        let resolver = QueryResolver::from_snapshot(
            self.adapter.as_ref(),
            self.project.root(),
            self.live_snapshot(),
        );
        let mut facts = resolver
            .resolve_rows_with_payload(rows.into_iter().map(|row| {
                let storage_key = HierarchyStorageKey {
                    blob_oid: row.candidate.blob_oid,
                    lang: row.candidate.lang.clone(),
                    unit_key: row.candidate.unit_key,
                };
                (row.candidate, (row.primary_range, storage_key))
            }))
            .into_iter()
            .map(
                |(declaration, (primary_range, storage_key))| HierarchyDeclarationFacts {
                    declaration,
                    primary_range,
                    imports: Arc::default(),
                    raw_supertypes: Arc::default(),
                    storage_key: Some(storage_key),
                },
            )
            .collect::<Vec<_>>();
        for state in self.dirty_file_states_for_queries() {
            facts.extend(
                state
                    .declarations
                    .iter()
                    .filter(|unit| !unit.is_file_scope() && unit.kind() == kind)
                    .cloned()
                    .map(|unit| {
                        let primary_range = state.ranges.get(&unit).and_then(|ranges| {
                            ranges
                                .iter()
                                .copied()
                                .min_by_key(|range| (range.start_line, range.start_byte))
                        });
                        let raw_supertypes =
                            state.raw_supertypes.get(&unit).cloned().unwrap_or_default();
                        HierarchyDeclarationFacts {
                            declaration: unit,
                            primary_range,
                            imports: Arc::from(state.imports.clone()),
                            raw_supertypes: Arc::from(raw_supertypes),
                            storage_key: None,
                        }
                    }),
            );
        }
        facts.extend(
            self.sql_nonpersisted_workspace_declarations_vec_matching(|unit| unit.kind() == kind)?
                .into_iter()
                .map(|declaration| HierarchyDeclarationFacts {
                    declaration,
                    primary_range: None,
                    imports: Arc::default(),
                    raw_supertypes: Arc::default(),
                    storage_key: None,
                }),
        );
        facts.sort_by(|left, right| left.declaration.cmp(&right.declaration));
        facts.dedup_by(|left, right| left.declaration == right.declaration);
        Some(facts)
    }

    pub(crate) fn hydrate_hierarchy_declaration_facts(
        &self,
        facts: &mut [HierarchyDeclarationFacts],
    ) -> Option<()> {
        let keys = facts
            .iter()
            .filter_map(|facts| facts.storage_key.clone())
            .collect::<Vec<_>>();
        let persisted = self.store_query_or_record(
            self.store_context
                .store
                .hierarchy_facts_by_keys(&keys, self.store_context.generations.as_ref()),
            "hydrating hierarchy declaration facts",
        )?;
        for facts in facts {
            let Some(storage_key) = facts.storage_key.as_ref() else {
                continue;
            };
            let Some(stored) = persisted.get(storage_key) else {
                continue;
            };
            facts.imports = Arc::clone(&stored.imports);
            facts.raw_supertypes = Arc::clone(&stored.raw_supertypes);
        }
        Some(())
    }

    fn definition_candidate_short_names(&self, fq_name: &str) -> Vec<String> {
        let mut names = self.adapter.lookup_candidate_short_names(fq_name);
        let normalized = self.adapter.normalize_full_name(fq_name);
        if normalized != fq_name {
            names.extend(self.adapter.lookup_candidate_short_names(&normalized));
        }
        names.sort();
        names.dedup();
        names
    }

    fn definition_sort_key_for_candidate(
        &self,
        candidate: &DefinitionSortCandidate,
    ) -> (i32, usize, String, String, String, String) {
        self.definition_sort_key(&candidate.unit, candidate.range_start)
    }

    fn definition_sort_key_for_unit(
        &self,
        code_unit: &CodeUnit,
    ) -> (i32, usize, String, String, String, String) {
        self.definition_sort_key(code_unit, DefinitionRangeStart::FileState)
    }

    fn definition_sort_key(
        &self,
        code_unit: &CodeUnit,
        range_start: DefinitionRangeStart,
    ) -> (i32, usize, String, String, String, String) {
        let first_start_byte = match range_start {
            DefinitionRangeStart::Persisted(first_start_byte) => {
                first_start_byte.unwrap_or(usize::MAX)
            }
            DefinitionRangeStart::FileState => self
                .ranges(code_unit)
                .into_iter()
                .map(|range| range.start_byte)
                .min()
                .unwrap_or(usize::MAX),
        };
        (
            self.adapter.definition_priority(code_unit),
            first_start_byte,
            code_unit.source().to_string().to_ascii_lowercase(),
            code_unit.fq_name().to_ascii_lowercase(),
            code_unit.signature().unwrap_or("").to_ascii_lowercase(),
            format!("{:?}", code_unit.kind()),
        )
    }

    fn sql_definitions_vec(&self, fq_name: &str) -> std::result::Result<Vec<CodeUnit>, StoreError> {
        self.sql_definitions_query_count
            .fetch_add(1, Ordering::Relaxed);
        self.sql_definition_candidates_vec(fq_name, false)
    }

    fn sql_bounded_definitions_vec(
        &self,
        fq_name: &str,
    ) -> std::result::Result<Vec<CodeUnit>, StoreError> {
        self.sql_definition_candidates_vec(fq_name, true)
    }

    fn sql_definition_candidates_vec(
        &self,
        fq_name: &str,
        include_definition_lookup_units: bool,
    ) -> std::result::Result<Vec<CodeUnit>, StoreError> {
        self.definition_candidates_query_count
            .fetch_add(1, Ordering::Relaxed);
        let normalized = self.adapter.normalize_full_name(fq_name);
        let langs = self.storage_language_keys_for_queries();
        let candidate_names = self.definition_candidate_short_names(fq_name);
        let rows = if candidate_names.is_empty() {
            Vec::new()
        } else {
            let mut rows = Vec::new();
            for short_name in candidate_names {
                let candidates = if include_definition_lookup_units {
                    self.store_context
                        .store
                        .definition_lookup_order_candidate_rows_by_short_name_for_langs(
                            &langs,
                            self.store_context.generations.as_ref(),
                            &short_name,
                        )
                } else {
                    self.store_context
                        .store
                        .declaration_order_candidate_rows_by_short_name_for_langs(
                            &langs,
                            self.store_context.generations.as_ref(),
                            &short_name,
                        )
                };
                rows.extend(candidates.map_err(|error| {
                    error.context(format!("querying definition candidates for `{fq_name}`"))
                })?);
            }
            rows
        };
        let mut candidates = self.resolve_definition_order_candidate_rows(rows);
        candidates.extend(
            self.dirty_units_matching(include_definition_lookup_units, |unit| {
                unit.fq_name() == fq_name
                    || self.adapter.normalize_full_name(&unit.fq_name()) == normalized
            })
            .into_iter()
            .map(|unit| DefinitionSortCandidate {
                unit,
                range_start: DefinitionRangeStart::FileState,
            }),
        );
        candidates.extend(
            self.sql_path_symbol_units(fq_name, &normalized)?
                .into_iter()
                .map(|unit| DefinitionSortCandidate {
                    unit,
                    range_start: DefinitionRangeStart::FileState,
                }),
        );
        let has_exact = candidates
            .iter()
            .any(|candidate| candidate.unit.fq_name() == fq_name);
        let mut matches: Vec<_> = candidates
            .into_iter()
            .filter(|candidate| {
                if has_exact {
                    candidate.unit.fq_name() == fq_name
                } else {
                    self.adapter.normalize_full_name(&candidate.unit.fq_name()) == normalized
                }
            })
            .collect();
        matches.sort_by_cached_key(|candidate| self.definition_sort_key_for_candidate(candidate));
        matches.dedup_by(|left, right| left.unit == right.unit);

        let mut saw_module = false;
        matches.retain(|candidate| {
            if !candidate.unit.is_module() {
                return true;
            }
            if saw_module {
                false
            } else {
                saw_module = true;
                true
            }
        });
        Ok(matches
            .into_iter()
            .map(|candidate| candidate.unit)
            .collect())
    }

    fn sql_lookup_candidates_by_short_name(&self, symbol: &str) -> Option<BTreeSet<CodeUnit>> {
        let candidate_names = self.definition_candidate_short_names(symbol);
        if candidate_names.is_empty() {
            return Some(BTreeSet::new());
        }

        let candidate_name_set: HashSet<_> = candidate_names.iter().cloned().collect();
        let langs = self.storage_language_keys_for_queries();
        let mut rows = Vec::new();
        for short_name in &candidate_names {
            rows.extend(
                self.store_query_or_record(
                    self.store_context
                        .store
                        .declaration_candidate_rows_by_short_name_for_langs(
                            &langs,
                            self.store_context.generations.as_ref(),
                            short_name,
                        ),
                    format!("querying declaration candidates for `{symbol}`"),
                )?,
            );
        }

        let mut matches: BTreeSet<_> = self
            .resolve_candidate_rows(rows)
            .into_iter()
            .filter(|unit| candidate_name_set.contains(unit.short_name()))
            .collect();
        matches.extend(
            self.dirty_units_matching(false, |unit| candidate_name_set.contains(unit.short_name())),
        );
        matches.extend(
            self.sql_nonpersisted_workspace_declarations_vec_matching(|unit| {
                candidate_name_set.contains(unit.short_name())
            })?,
        );
        Some(matches)
    }

    pub(crate) fn lookup_declarations_by_identifier(&self, identifier: &str) -> BTreeSet<CodeUnit> {
        let langs = self.storage_language_keys_for_queries();
        let rows = self
            .store_query_or_record(
                self.store_context
                    .store
                    .declaration_candidate_rows_by_identifier_for_langs(
                        &langs,
                        self.store_context.generations.as_ref(),
                        identifier,
                    ),
                format!("querying declarations by identifier `{identifier}`"),
            )
            .unwrap_or_default();
        let mut matches: BTreeSet<_> = self
            .resolve_candidate_rows(rows)
            .into_iter()
            .filter(|unit| unit.identifier() == identifier)
            .collect();
        matches.extend(self.dirty_units_matching(false, |unit| unit.identifier() == identifier));
        matches.extend(
            self.sql_nonpersisted_workspace_declarations_vec_matching(|unit| {
                unit.identifier() == identifier
            })
            .unwrap_or_default(),
        );
        matches
    }

    pub(crate) fn lookup_declarations_by_persisted_fqn(
        &self,
        fqn: &str,
        normalized: bool,
    ) -> BTreeSet<CodeUnit> {
        use crate::analyzer::store::PersistedLookupKey;
        let key = if normalized {
            PersistedLookupKey::NormalizedFqn
        } else {
            PersistedLookupKey::ExactFqn
        };
        let lookup = if normalized {
            self.adapter.normalize_full_name(fqn)
        } else {
            fqn.to_string()
        };
        let rows = self
            .store_query_or_record(
                self.store_context
                    .store
                    .declaration_candidate_rows_by_lookup_key_for_langs(
                        &self.storage_language_keys_for_queries(),
                        self.store_context.generations.as_ref(),
                        key,
                        &lookup,
                    ),
                format!("querying declarations by persisted name `{lookup}`"),
            )
            .unwrap_or_default();
        let mut matches: BTreeSet<_> = self.resolve_candidate_rows(rows).into_iter().collect();
        matches.extend(self.dirty_units_matching(false, |unit| {
            let candidate = if normalized {
                self.adapter.normalize_full_name(&unit.fq_name())
            } else {
                unit.fq_name()
            };
            candidate == lookup
        }));
        matches.extend(
            self.sql_nonpersisted_workspace_declarations_vec_matching(|unit| {
                let candidate = if normalized {
                    self.adapter.normalize_full_name(&unit.fq_name())
                } else {
                    unit.fq_name()
                };
                candidate == lookup
            })
            .unwrap_or_default(),
        );
        matches
    }

    pub(crate) fn lookup_members_for_owner_name(
        &self,
        owner_fqn: &str,
        name: &str,
    ) -> BTreeSet<CodeUnit> {
        let exact_rows = self
            .store_query_or_record(
                self.store_context
                    .store
                    .declaration_member_rows_for_owner_for_langs(
                        &self.storage_language_keys_for_queries(),
                        self.store_context.generations.as_ref(),
                        owner_fqn,
                        false,
                        name,
                    ),
                format!("querying members named `{name}` for `{owner_fqn}`"),
            )
            .unwrap_or_default();
        let mut matches: BTreeSet<_> = self
            .resolve_candidate_rows(exact_rows)
            .into_iter()
            .collect();
        matches.extend(self.dirty_units_matching(false, |unit| {
            unit.identifier() == name && unit.fq_name() == format!("{owner_fqn}.{name}")
        }));
        matches.extend(
            self.sql_nonpersisted_workspace_declarations_vec_matching(|unit| {
                unit.identifier() == name && unit.fq_name() == format!("{owner_fqn}.{name}")
            })
            .unwrap_or_default(),
        );
        if !matches.is_empty() {
            return matches;
        }

        let normalized_owner = self.adapter.normalize_full_name(owner_fqn);
        let normalized_rows = self
            .store_query_or_record(
                self.store_context
                    .store
                    .declaration_member_rows_for_owner_for_langs(
                        &self.storage_language_keys_for_queries(),
                        self.store_context.generations.as_ref(),
                        &normalized_owner,
                        true,
                        name,
                    ),
                format!("querying normalized members named `{name}` for `{owner_fqn}`"),
            )
            .unwrap_or_default();
        matches.extend(self.resolve_candidate_rows(normalized_rows));
        let normalized_member = self
            .adapter
            .normalize_full_name(&format!("{owner_fqn}.{name}"));
        matches.extend(self.dirty_units_matching(false, |unit| {
            unit.identifier() == name
                && self.adapter.normalize_full_name(&unit.fq_name()) == normalized_member
        }));
        matches.extend(
            self.sql_nonpersisted_workspace_declarations_vec_matching(|unit| {
                unit.identifier() == name
                    && self.adapter.normalize_full_name(&unit.fq_name()) == normalized_member
            })
            .unwrap_or_default(),
        );
        matches
    }

    pub(crate) fn persisted_package_exists(&self, package: &str) -> bool {
        if !self
            .dirty_units_matching(false, |unit| unit.package_name() == package)
            .is_empty()
        {
            return true;
        }
        let rows = self
            .store_query_or_record(
                self.store_context
                    .store
                    .declaration_rows_by_package_for_langs(
                        &self.storage_language_keys_for_queries(),
                        self.store_context.generations.as_ref(),
                        package,
                    ),
                format!("querying declarations in package `{package}`"),
            )
            .unwrap_or_default();
        self.resolve_candidate_rows(rows)
            .into_iter()
            .any(|unit| unit.package_name() == package)
    }

    fn sql_search_definitions(
        &self,
        pattern: &str,
        auto_quote: bool,
    ) -> Option<BTreeSet<CodeUnit>> {
        if pattern.is_empty() {
            return Some(BTreeSet::new());
        }

        let pattern = if auto_quote {
            if pattern.contains(".*") {
                pattern.to_string()
            } else {
                format!(".*?{}.*?", regex::escape(pattern))
            }
        } else {
            pattern.to_string()
        };
        let compiled = RegexBuilder::new(&pattern)
            .case_insensitive(true)
            .build()
            .ok()?;
        let storage_languages = self.storage_language_keys_for_queries();
        let rows = if self
            .adapter
            .persisted_content_qualifier_supports_substring_search()
            && literal_ascii_search_substring(&pattern).is_some()
        {
            self.store_query_or_record(
                self.store_context
                    .store
                    .declaration_candidate_rows_by_literal_substring_for_langs(
                        &storage_languages,
                        self.store_context.generations.as_ref(),
                        &pattern,
                    ),
                format!("searching definitions for `{pattern}`"),
            )?
        } else {
            self.store_query_or_record(
                self.store_context
                    .store
                    .declaration_candidate_rows_by_pattern_for_langs(
                        &storage_languages,
                        self.store_context.generations.as_ref(),
                        &pattern,
                    ),
                format!("searching definitions for `{pattern}`"),
            )?
        };
        let mut out: BTreeSet<_> = self
            .resolve_candidate_rows(rows)
            .into_iter()
            .filter(|unit| {
                let fq_name = self.adapter.normalize_full_name(&unit.fq_name());
                !self.adapter.is_anonymous_structure(&fq_name) && compiled.is_match(&fq_name)
            })
            .collect();
        out.extend(self.dirty_units_matching(false, |unit| {
            let fq_name = self.adapter.normalize_full_name(&unit.fq_name());
            !self.adapter.is_anonymous_structure(&fq_name) && compiled.is_match(&fq_name)
        }));
        out.extend(
            self.sql_nonpersisted_workspace_declarations_vec_matching(|unit| {
                let fq_name = self.adapter.normalize_full_name(&unit.fq_name());
                !self.adapter.is_anonymous_structure(&fq_name) && compiled.is_match(&fq_name)
            })?,
        );
        Some(out)
    }

    fn sql_search_symbol_candidates(
        &self,
        pattern: &str,
        auto_quote: bool,
    ) -> Option<Vec<SearchSymbolCandidate>> {
        if pattern.is_empty() {
            return Some(Vec::new());
        }

        let pattern = if auto_quote {
            if pattern.contains(".*") {
                pattern.to_string()
            } else {
                format!(".*?{}.*?", regex::escape(pattern))
            }
        } else {
            escape_sigil_anchors(pattern)
        };
        let compiled = RegexBuilder::new(&pattern)
            .case_insensitive(true)
            .build()
            .ok()?;
        let rows = self.store_query_or_record(
            self.store_context
                .store
                .search_candidate_rows_by_pattern_for_langs(
                    &self.storage_language_keys_for_queries(),
                    self.store_context.generations.as_ref(),
                    &pattern,
                ),
            format!("searching symbol candidates for `{pattern}`"),
        )?;
        let resolver = QueryResolver::from_snapshot(
            self.adapter.as_ref(),
            self.project.root(),
            self.live_snapshot(),
        );
        let mut candidates = BTreeMap::new();
        for (code_unit, (primary_range, contains_tests)) in resolver.resolve_rows_with_payload(
            rows.into_iter()
                .map(|row| (row.candidate, (row.primary_range, row.contains_tests))),
        ) {
            let fq_name = self.adapter.normalize_full_name(&code_unit.fq_name());
            if !self.adapter.is_anonymous_structure(&fq_name) && compiled.is_match(&fq_name) {
                candidates
                    .entry(code_unit.clone())
                    .or_insert(SearchSymbolCandidate {
                        code_unit,
                        primary_range,
                        contains_tests,
                    });
            }
        }

        for code_unit in self.dirty_units_matching(false, |unit| {
            let fq_name = self.adapter.normalize_full_name(&unit.fq_name());
            !self.adapter.is_anonymous_structure(&fq_name) && compiled.is_match(&fq_name)
        }) {
            candidates
                .entry(code_unit.clone())
                .or_insert_with(|| SearchSymbolCandidate {
                    primary_range: self
                        .ranges(&code_unit)
                        .into_iter()
                        .min_by_key(|range| (range.start_line, range.start_byte)),
                    contains_tests: self.contains_tests(code_unit.source()),
                    code_unit,
                });
        }
        for code_unit in self.sql_nonpersisted_workspace_declarations_vec_matching(|unit| {
            let fq_name = self.adapter.normalize_full_name(&unit.fq_name());
            !self.adapter.is_anonymous_structure(&fq_name) && compiled.is_match(&fq_name)
        })? {
            candidates
                .entry(code_unit.clone())
                .or_insert_with(|| SearchSymbolCandidate {
                    primary_range: self
                        .ranges(&code_unit)
                        .into_iter()
                        .min_by_key(|range| (range.start_line, range.start_byte)),
                    contains_tests: self.contains_tests(code_unit.source()),
                    code_unit,
                });
        }

        Some(candidates.into_values().collect())
    }

    pub(crate) fn package_name_of(&self, file: &ProjectFile) -> Option<String> {
        self.fetch_file_state(file)
            .map(|state| state.package_name.clone())
    }

    pub(crate) fn content_qualifier_of(&self, file: &ProjectFile) -> Option<String> {
        let oid = self.resolve_live_oid_for_file(file)?;
        let key = Self::transient_cache_key(oid, file);
        if let Some(content_qualifier) = self.state.dirty_content_qualifier(&key) {
            return Some(content_qualifier);
        }
        let storage_key = self.adapter.storage_language_key_for_file(file);
        self.store_query_or_record(
            self.store_context.store.content_package(
                oid,
                &storage_key,
                self.store_context.generations[&storage_key],
            ),
            format!("querying the content qualifier for `{file}`"),
        )
        .flatten()
        .or_else(|| {
            self.source_snapshot_file_state(file)
                .map(|state| state.content_qualifier.clone())
        })
        .or_else(|| {
            self.fetch_file_state(file)
                .map(|state| state.content_qualifier.clone())
        })
    }

    pub(crate) fn ruby_method_dispatch_mode(
        &self,
        code_unit: &CodeUnit,
    ) -> Option<RubyMethodDispatchMode> {
        self.fetch_file_state(code_unit.source())
            .and_then(|state| state.ruby_method_dispatch_modes.get(code_unit).copied())
    }

    pub(crate) fn import_info_of(&self, file: &ProjectFile) -> Vec<ImportInfo> {
        let Some(oid) = self.resolve_live_oid_for_file(file) else {
            return Vec::new();
        };
        let key = Self::transient_cache_key(oid, file);
        if let Some(imports) = self.state.dirty_imports(&key) {
            return imports;
        }
        let storage_key = self.adapter.storage_language_key_for_file(file);
        self.store_query_or_record(
            self.store_context.store.hydrate_import_infos_by_key(
                &[(file.clone(), oid, storage_key)],
                self.store_context.generations.as_ref(),
                self.adapter.as_ref(),
            ),
            format!("hydrating imports for `{file}`"),
        )
        .and_then(|mut imports| imports.remove(file))
        .or_else(|| {
            self.source_snapshot_file_state(file)
                .map(|state| state.imports.clone())
        })
        .or_else(|| {
            self.fetch_file_state(file)
                .map(|state| state.imports.clone())
        })
        .unwrap_or_default()
    }

    pub(crate) fn raw_supertypes_of(&self, code_unit: &CodeUnit) -> Vec<String> {
        let Some(state) = self.fetch_file_state(code_unit.source()) else {
            return Vec::new();
        };
        state
            .raw_supertypes
            .get(code_unit)
            .cloned()
            .or_else(|| {
                state
                    .raw_supertypes
                    .iter()
                    .find(|(owner, _)| {
                        owner.source() == code_unit.source()
                            && owner.kind() == code_unit.kind()
                            && owner.fq_name() == code_unit.fq_name()
                    })
                    .map(|(_, raw)| raw.clone())
            })
            .unwrap_or_default()
    }

    pub(crate) fn is_scala_trait(&self, code_unit: &CodeUnit) -> bool {
        self.fetch_file_state(code_unit.source())
            .is_some_and(|state| state.scala_traits.contains(code_unit))
    }

    pub(crate) fn scala_traits(&self) -> Vec<CodeUnit> {
        self.sql_all_declarations_vec()
            .unwrap_or_default()
            .into_iter()
            .filter(|unit| self.is_scala_trait(unit))
            .collect()
    }

    pub(crate) fn type_identifiers_of(&self, file: &ProjectFile) -> Option<HashSet<String>> {
        self.fetch_file_state(file)
            .map(|state| state.type_identifiers.clone())
    }

    pub(crate) fn all_files(&self) -> Vec<ProjectFile> {
        self.analyzed_live_files()
    }

    pub(crate) fn class_declarations_in_package(&self, package_name: &str) -> Vec<CodeUnit> {
        let rows = self
            .store_query_or_record(
                self.store_context
                    .store
                    .declaration_candidate_rows_for_langs(
                        &self.storage_language_keys_for_queries(),
                        self.store_context.generations.as_ref(),
                    ),
                format!("querying class declarations in package `{package_name}`"),
            )
            .unwrap_or_default()
            .into_iter()
            .filter(|row| row.kind == CodeUnitType::Class && row.flags.is_top_level);
        let mut matches: Vec<_> = self
            .resolve_candidate_rows(rows.collect())
            .into_iter()
            .filter(|unit| unit.package_name() == package_name)
            .collect();
        matches.extend(self.dirty_units_matching(false, |unit| {
            unit.is_class() && unit.package_name() == package_name
        }));
        matches.extend(
            self.sql_nonpersisted_workspace_declarations_vec_matching(|unit| {
                unit.is_class() && unit.package_name() == package_name
            })
            .unwrap_or_default(),
        );

        matches.sort_by_cached_key(|code_unit| self.definition_sort_key_for_unit(code_unit));
        matches.dedup();
        matches
    }

    pub(crate) fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
        self.fetch_file_state(code_unit.source())
            .map(|state| state.type_aliases.contains(code_unit))
            .unwrap_or(false)
    }

    pub(crate) fn signatures_vec_of(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.fetch_file_state(code_unit.source())
            .and_then(|state| state.signatures.get(code_unit).cloned())
            .unwrap_or_default()
    }

    pub(crate) fn signature_metadata_vec_of(&self, code_unit: &CodeUnit) -> Vec<SignatureMetadata> {
        self.fetch_file_state(code_unit.source())
            .and_then(|state| state.signature_metadata.get(code_unit).cloned())
            .unwrap_or_default()
    }

    pub(crate) fn cpp_template_metadata_of(
        &self,
        code_unit: &CodeUnit,
    ) -> Option<CppTemplateMetadata> {
        self.fetch_file_state(code_unit.source())
            .and_then(|state| state.cpp_template_metadata.get(code_unit).cloned())
    }

    fn source_slice(
        &self,
        code_unit: &CodeUnit,
        range: &Range,
        include_comments: bool,
    ) -> Option<String> {
        let file_state = self
            .source_snapshot_file_state(code_unit.source())
            .or_else(|| self.fetch_file_state(code_unit.source()))?;
        let start_byte = if include_comments {
            expanded_comment_start(&file_state.source, range.start_byte)
        } else {
            range.start_byte
        };
        file_state
            .source
            .get(start_byte..range.end_byte)
            .map(str::to_string)
    }

    fn render_skeleton_recursive(
        &self,
        code_unit: &CodeUnit,
        indent: &str,
        header_only: bool,
        out: &mut String,
    ) {
        for signature in self.signatures_vec_of(code_unit) {
            if signature.is_empty() {
                continue;
            }
            for line in signature.lines() {
                out.push_str(indent);
                out.push_str(line);
                out.push('\n');
            }
        }

        let all_children: Vec<_> =
            <Self as crate::analyzer::IAnalyzer>::direct_children(self, code_unit)
                .into_iter()
                .filter(|child| {
                    !child.is_synthetic()
                        || !<Self as crate::analyzer::IAnalyzer>::ranges(self, child).is_empty()
                })
                .collect();
        let field_children: Vec<_> = all_children
            .iter()
            .filter(|child| child.is_field())
            .cloned()
            .collect();
        let parent_start = <Self as crate::analyzer::IAnalyzer>::ranges(self, code_unit)
            .into_iter()
            .map(|range| range.start_byte)
            .min()
            .unwrap_or(usize::MAX);
        let non_field_children: Vec<_> = all_children
            .iter()
            .filter(|child| !child.is_field())
            .cloned()
            .collect();
        let children = if header_only {
            field_children.clone()
        } else {
            field_children
                .iter()
                .chain(
                    non_field_children
                        .iter()
                        .filter(|child| Self::child_first_start(self, child) >= parent_start),
                )
                .chain(
                    non_field_children
                        .iter()
                        .filter(|child| Self::child_first_start(self, child) < parent_start),
                )
                .cloned()
                .collect()
        };

        if !children.is_empty() || code_unit.is_class() {
            let child_indent = format!("{indent}  ");
            for child in children {
                self.render_skeleton_recursive(&child, &child_indent, header_only, out);
            }
            if header_only && !non_field_children.is_empty() {
                out.push_str(&child_indent);
                out.push_str("[...]\n");
            }
            if code_unit.is_class() {
                out.push_str(indent);
                out.push_str("}\n");
            }
        }
    }
}

impl<A> TreeSitterAnalyzer<A>
where
    A: LanguageAdapter,
{
    fn record_store_error(&self, error: StoreError) {
        let contexts = self
            .query_read_cache
            .lock()
            .expect("query read cache mutex poisoned")
            .contexts
            .clone();
        for context in contexts {
            context.record_store_error(error.clone());
        }
    }

    fn store_query_or_record<T>(
        &self,
        result: std::result::Result<T, StoreError>,
        operation: impl std::fmt::Display,
    ) -> Option<T> {
        match result {
            Ok(value) => Some(value),
            Err(error) => {
                self.record_store_error(error.context(operation));
                None
            }
        }
    }

    fn child_first_start(&self, child: &CodeUnit) -> usize {
        <Self as crate::analyzer::IAnalyzer>::ranges(self, child)
            .into_iter()
            .map(|range| range.start_byte)
            .min()
            .unwrap_or(usize::MAX)
    }

    /// Owned handle to the workspace definition index. A refcount bump, not a
    /// map clone; used by per-query views that must outlive a borrow of the
    /// analyzer (e.g. Scala's `ProjectTypes` behind `Arc` caches).
    pub(crate) fn global_usage_definition_index_shared(&self) -> Arc<GlobalUsageDefinitionIndex> {
        Arc::clone(self.global_usage_definition_index_handle())
    }

    /// Owned handle to the derived callable-facts index; see
    /// [`Self::global_usage_definition_index_shared`].
    pub(crate) fn usage_facts_index_shared(&self) -> Arc<UsageFactsIndex> {
        Arc::clone(self.usage_facts_index_handle())
    }

    fn global_usage_definition_index_handle(&self) -> &Arc<GlobalUsageDefinitionIndex> {
        match self.try_global_usage_definition_index_handle() {
            Ok(index) => index,
            Err(error) => {
                self.record_store_error(
                    error.context("building the global usage definition index"),
                );
                &self.global_usage_definition_fallback
            }
        }
    }

    fn try_global_usage_definition_index_handle(
        &self,
    ) -> std::result::Result<&Arc<GlobalUsageDefinitionIndex>, StoreError> {
        if let Some(index) = self.global_usage_definition_index.get() {
            return Ok(index);
        }
        let _init = self
            .global_usage_definition_index_init
            .lock()
            .expect("definition index initialization lock poisoned");
        if let Some(index) = self.global_usage_definition_index.get() {
            return Ok(index);
        }
        let _scope = profiling::scope("TreeSitterAnalyzer::global_usage_definition_index_build");
        let build_count = self
            .global_usage_definition_index_build_count
            .fetch_add(1, Ordering::Relaxed)
            + 1;
        if profiling::enabled() {
            profiling::note(format!(
                "language={:?} build_count={build_count}",
                self.adapter.language()
            ));
        }
        let built = Arc::new(self.sql_global_usage_definition_index()?);
        self.global_usage_definition_index
            .set(built)
            .expect("definition index initialization is serialized");
        Ok(self
            .global_usage_definition_index
            .get()
            .expect("successful definition index build initializes OnceLock"))
    }

    fn usage_facts_index_handle(&self) -> &Arc<UsageFactsIndex> {
        match self.try_usage_facts_index_handle() {
            Ok(index) => index,
            Err(error) => {
                self.record_store_error(error.context("building the usage facts index"));
                &self.usage_facts_fallback
            }
        }
    }

    fn try_usage_facts_index_handle(
        &self,
    ) -> std::result::Result<&Arc<UsageFactsIndex>, StoreError> {
        if let Some(index) = self.usage_facts_index.get() {
            return Ok(index);
        }
        let _init = self
            .usage_facts_index_init
            .lock()
            .expect("usage facts initialization lock poisoned");
        if let Some(index) = self.usage_facts_index.get() {
            return Ok(index);
        }
        let built = Arc::new(self.build_usage_facts_index()?);
        self.usage_facts_index
            .set(built)
            .expect("usage facts initialization is serialized");
        Ok(self
            .usage_facts_index
            .get()
            .expect("successful usage facts build initializes OnceLock"))
    }

    fn build_usage_facts_index(&self) -> std::result::Result<UsageFactsIndex, StoreError> {
        self.full_declaration_scan_count
            .fetch_add(1, Ordering::Relaxed);
        let storage_languages = self.storage_language_keys_for_queries();
        let (declaration_rows, rows) = self
            .store_context
            .store
            .declaration_and_usage_fact_rows_for_langs(
                &storage_languages,
                self.store_context.generations.as_ref(),
            )?;
        let mut declarations = self.resolve_candidate_rows(declaration_rows);
        declarations.extend(self.dirty_units_matching(false, |_| true));
        declarations
            .extend(self.try_sql_nonpersisted_workspace_declarations_vec_matching(|_| true)?);
        declarations.retain(|unit| !unit.is_file_scope());
        declarations.sort();
        declarations.dedup();
        let resolver = QueryResolver::from_snapshot(
            self.adapter.as_ref(),
            self.project.root(),
            self.live_snapshot(),
        );
        let mut facts_by_declaration = HashMap::default();
        for (unit, row) in resolver.resolve_rows_with_payload(
            rows.into_iter()
                .map(|row| (row.candidate, (row.signature, row.signature_metadata))),
        ) {
            facts_by_declaration.insert(unit, row);
        }
        for state in self.dirty_file_states_for_queries() {
            for unit in &state.declarations {
                facts_by_declaration.insert(
                    unit.clone(),
                    (
                        state
                            .signatures
                            .get(unit)
                            .and_then(|signatures| signatures.first())
                            .cloned(),
                        state
                            .signature_metadata
                            .get(unit)
                            .and_then(|metadata| metadata.first())
                            .cloned(),
                    ),
                );
            }
        }
        Ok(UsageFactsIndex::build_from_declarations(
            self.try_global_usage_definition_index_handle()?.as_ref(),
            declarations.iter(),
            |unit| {
                facts_by_declaration
                    .get(unit)
                    .and_then(|(signature, _)| signature.clone())
                    .or_else(|| unit.signature().map(str::to_string))
            },
            |unit| {
                facts_by_declaration
                    .get(unit)
                    .and_then(|(_, metadata)| metadata.clone())
            },
            self.adapter.as_ref(),
        ))
    }
}

impl<A> crate::analyzer::IAnalyzer for TreeSitterAnalyzer<A>
where
    A: LanguageAdapter,
{
    fn begin_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        let mut cache = self
            .query_read_cache
            .lock()
            .expect("query read cache mutex poisoned");
        cache.begin(context);
    }

    fn end_query(&self, context: &Arc<crate::analyzer::AnalyzerQueryContext>) {
        let mut cache = self
            .query_read_cache
            .lock()
            .expect("query read cache mutex poisoned");
        cache.end(context);
    }

    fn top_level_declarations(&self, file: &ProjectFile) -> Vec<CodeUnit> {
        self.fetch_file_state(file)
            .map(|state| {
                state
                    .top_level_declarations
                    .iter()
                    .filter(|code_unit| !code_unit.is_file_scope())
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    fn summary_file_projection(&self, file: &ProjectFile) -> Option<Arc<SummaryFileProjection>> {
        let _scope = profiling::scope(format!(
            "TreeSitterAnalyzer::{:?}::summary_file_projection",
            self.adapter.language()
        ));
        if self.project.has_overlay(file) {
            return None;
        }
        let oid = self.resolve_live_oid_for_file(file)?;
        let cache_key = Self::transient_cache_key(oid, file);
        if let Some(projection) = self
            .summary_file_projections
            .lock()
            .expect("summary file projection cache mutex poisoned")
            .get(&cache_key)
        {
            return Some(projection);
        }
        let storage_key = self.adapter.storage_language_key_for_file(file);
        let projection = self
            .store_query_or_record(
                self.store_context.store.summary_file_projection(
                    oid,
                    &storage_key,
                    self.store_context.generations[&storage_key],
                    self.adapter.as_ref(),
                    file,
                ),
                format!("hydrating summary projection for `{file}`"),
            )
            .flatten()?;
        let projection = Arc::new(projection);
        self.summary_file_projections
            .lock()
            .expect("summary file projection cache mutex poisoned")
            .insert(cache_key, Arc::clone(&projection));
        Some(projection)
    }

    fn analyzed_files(&self) -> Vec<ProjectFile> {
        self.analyzed_live_files()
    }

    fn indexed_source(&self, file: &ProjectFile) -> Option<String> {
        self.file_source(file)
    }

    fn indexed_source_matches(&self, file: &ProjectFile, source: &str) -> bool {
        let Some(indexed_oid) = self.live_snapshot().oid_for_path(file) else {
            return false;
        };
        Oid::hash_object(ObjectType::Blob, source.as_bytes()).ok() == Some(indexed_oid)
    }

    fn is_analyzed(&self, file: &ProjectFile) -> bool {
        let Some(oid) = self.resolve_live_oid_for_file(file) else {
            return false;
        };
        crate::analyzer::common::language_for_file(file) == self.adapter.language() && {
            let storage_key = self.adapter.storage_language_key_for_file(file);
            let key = Self::transient_cache_key(oid, file);
            self.retry_dirty_file_state(&key, &storage_key).is_some()
                || self
                    .store_query_or_record(
                        self.store_context.store.contains_parsed_blob_at_generation(
                            oid,
                            &storage_key,
                            self.store_context.generations[&storage_key],
                        ),
                        format!("checking whether `{file}` is analyzed"),
                    )
                    .unwrap_or(false)
        }
    }

    fn languages(&self) -> BTreeSet<Language> {
        BTreeSet::from([self.adapter.language()])
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        if changed_files.is_empty() {
            return self.clone();
        }

        let mut store_context = self.store_context.clone();
        store_context.live_paths = Arc::new(self.store_context.live_paths.fork());
        let mut to_update = Vec::new();
        let mut dirty_file_states = self.state.dirty_snapshot();
        let mut dirty_path_symbol_rows = self.state.dirty_path_symbol_snapshot();

        for file in changed_files {
            Self::remove_dirty_for_file(&mut dirty_file_states, file);
            if !file.exists() && !self.project.has_overlay(file) {
                store_context
                    .live_paths
                    .remove(std::iter::once(file.clone()));
                if let Some(liveness) = store_context.liveness.as_ref() {
                    liveness.remove_overlay_paths(std::iter::once(file.clone()));
                }
                continue;
            }
            to_update.push(file.clone());
        }

        let state = Self::reconcile_file_states(
            self.project.as_ref(),
            self.adapter.as_ref(),
            &self.config,
            &store_context,
            ReconcileFileStates {
                files: to_update,
                replace_live_paths: false,
                progress: None,
                dirty_file_states,
                dirty_path_symbol_rows,
            },
        );
        dirty_path_symbol_rows = state.dirty_path_symbol_snapshot();
        Self::refresh_path_symbol_units(
            self.adapter.as_ref(),
            changed_files,
            &store_context,
            &mut dirty_path_symbol_rows,
        );
        *state
            .dirty_path_symbol_rows
            .lock()
            .expect("dirty path-symbol mutex poisoned") = dirty_path_symbol_rows;
        store_context
            .gc
            .schedule(self.project.root(), Arc::clone(&store_context.store));
        Self::from_state(
            Arc::clone(&self.project),
            Arc::clone(&self.adapter),
            self.config.clone(),
            state,
            Arc::clone(&self.structural_cache),
            self.semantic_cache.clone(),
            store_context,
        )
    }

    fn update_all(&self) -> Self {
        let mut store_context = self.store_context.clone();
        store_context.live_paths = Arc::new(self.store_context.live_paths.fork());
        let state = Self::build_state(
            self.project.as_ref(),
            self.adapter.as_ref(),
            &self.config,
            None,
            &store_context,
        );
        Self::from_state(
            Arc::clone(&self.project),
            Arc::clone(&self.adapter),
            self.config.clone(),
            state,
            Arc::clone(&self.structural_cache),
            self.semantic_cache.clone(),
            store_context,
        )
    }

    fn project(&self) -> &dyn Project {
        self.project()
    }

    fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        Box::new(
            self.sql_all_declarations_vec()
                .unwrap_or_default()
                .into_iter(),
        )
    }

    fn all_declarations_with_primary_ranges(&self) -> Vec<(CodeUnit, Option<Range>)> {
        self.sql_all_declarations_with_primary_ranges_vec()
            .unwrap_or_default()
    }

    fn declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        self.fetch_file_state(file)
            .map(|state| {
                state
                    .declarations
                    .iter()
                    .filter(|unit| !unit.is_file_scope())
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    fn definitions(&self, fq_name: &str) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
        let definitions = match self.sql_definitions_vec(fq_name) {
            Ok(definitions) => definitions,
            Err(error) => {
                self.record_store_error(error);
                Vec::new()
            }
        };
        Box::new(definitions.into_iter())
    }

    fn global_usage_definition_index(&self) -> &GlobalUsageDefinitionIndex {
        self.global_usage_definition_index_handle().as_ref()
    }

    fn reset_global_usage_definition_index_build_count_for_test(&self) {
        TreeSitterAnalyzer::reset_global_usage_definition_index_build_count_for_test(self);
    }

    fn global_usage_definition_index_build_count_for_test(&self) -> usize {
        TreeSitterAnalyzer::global_usage_definition_index_build_count_for_test(self)
    }

    fn reset_definition_candidates_query_count_for_test(&self) {
        TreeSitterAnalyzer::reset_definition_candidates_query_count_for_test(self);
    }

    fn definition_candidates_query_count_for_test(&self) -> usize {
        TreeSitterAnalyzer::definition_candidates_query_count_for_test(self)
    }

    fn reset_full_declaration_scan_count_for_test(&self) {
        TreeSitterAnalyzer::reset_full_declaration_scan_count_for_test(self);
    }

    fn full_declaration_scan_count_for_test(&self) -> usize {
        TreeSitterAnalyzer::full_declaration_scan_count_for_test(self)
    }

    fn reset_candidate_hydration_count_for_test(&self) {
        TreeSitterAnalyzer::reset_full_hydration_count_for_test(self);
    }

    fn candidate_hydration_count_for_test(&self) -> usize {
        TreeSitterAnalyzer::full_hydration_count_for_test(self)
            + TreeSitterAnalyzer::bulk_hydration_count_for_test(self)
    }

    fn full_candidate_hydration_count_for_test(&self) -> usize {
        TreeSitterAnalyzer::full_hydration_count_for_test(self)
    }

    fn bulk_candidate_hydration_count_for_test(&self) -> usize {
        TreeSitterAnalyzer::bulk_hydration_count_for_test(self)
    }

    fn reset_workspace_path_scan_count_for_test(&self) {
        TreeSitterAnalyzer::reset_workspace_path_scan_count_for_test(self);
    }

    fn workspace_path_scan_count_for_test(&self) -> usize {
        TreeSitterAnalyzer::workspace_path_scan_count_for_test(self)
    }

    fn usage_facts_index(&self) -> &UsageFactsIndex {
        self.usage_facts_index_handle().as_ref()
    }

    fn direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        if code_unit.is_module() && self.adapter.language() == Language::Java {
            return self.class_declarations_in_package(&code_unit.fq_name());
        }

        self.fetch_file_state(code_unit.source())
            .and_then(|state| {
                let mut children = state.children.get(code_unit).cloned()?;
                Self::canonicalize_children(&mut children, &state.ranges);
                Some(children)
            })
            .unwrap_or_default()
    }

    fn parse_errors(&self, file: &ProjectFile) -> Option<Vec<crate::analyzer::ParseError>> {
        self.state.fresh_parse_errors.get(file).cloned()
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        self.adapter.extract_call_receiver(reference)
    }

    fn import_statements(&self, file: &ProjectFile) -> Vec<String> {
        self.fetch_file_state(file)
            .map(|state| state.import_statements.clone())
            .unwrap_or_default()
    }

    fn structural_search_providers(
        &self,
    ) -> Vec<&dyn crate::analyzer::structural::StructuralSearchProvider> {
        if self.adapter.structural_spec().is_some() {
            vec![self]
        } else {
            Vec::new()
        }
    }

    fn enclosing_code_unit(&self, file: &ProjectFile, range: &Range) -> Option<CodeUnit> {
        self.enclosing_code_unit_query_count
            .fetch_add(1, Ordering::Relaxed);
        if range.start_byte >= range.end_byte {
            return None;
        }

        self.fetch_file_state(file)?
            .declarations
            .iter()
            .cloned()
            .filter_map(|code_unit| {
                let best_range = self
                    .ranges(&code_unit)
                    .into_iter()
                    .find(|candidate| candidate.contains(range))?;
                Some((best_range.end_byte - best_range.start_byte, code_unit))
            })
            .min_by(|(left_span, left), (right_span, right)| {
                left_span
                    .cmp(right_span)
                    .then_with(|| {
                        enclosing_code_unit_rank(left).cmp(&enclosing_code_unit_rank(right))
                    })
                    .then_with(|| left.fq_name().cmp(&right.fq_name()))
                    .then_with(|| left.kind().cmp(&right.kind()))
                    .then_with(|| left.source().rel_path().cmp(right.source().rel_path()))
            })
            .map(|(_, code_unit)| code_unit)
    }

    fn enclosing_code_unit_for_lines(
        &self,
        file: &ProjectFile,
        start_line: usize,
        end_line: usize,
    ) -> Option<CodeUnit> {
        let line_range = Range {
            start_byte: 0,
            end_byte: usize::MAX,
            start_line,
            end_line,
        };
        self.declarations(file)
            .into_iter()
            .filter_map(|code_unit| {
                let best_range = self.ranges(&code_unit).into_iter().find(|candidate| {
                    candidate.start_line <= line_range.start_line
                        && candidate.end_line >= line_range.end_line
                })?;
                Some((best_range.end_line - best_range.start_line, code_unit))
            })
            .min_by_key(|(span, _)| *span)
            .map(|(_, code_unit)| code_unit)
    }

    fn is_access_expression(
        &self,
        _file: &ProjectFile,
        _start_byte: usize,
        _end_byte: usize,
    ) -> bool {
        true
    }

    fn find_nearest_declaration(
        &self,
        _file: &ProjectFile,
        _start_byte: usize,
        _end_byte: usize,
        _ident: &str,
    ) -> Option<DeclarationInfo> {
        None
    }

    fn ranges(&self, code_unit: &CodeUnit) -> Vec<Range> {
        self.source_snapshot_file_state(code_unit.source())
            .or_else(|| self.fetch_file_state(code_unit.source()))
            .and_then(|state| state.ranges.get(code_unit).cloned())
            .unwrap_or_default()
    }

    fn compute_cognitive_complexities(&self, file: &ProjectFile) -> Vec<(CodeUnit, u32)> {
        let Some(config) = self.adapter.cognitive_complexity_config() else {
            return Vec::new();
        };
        let Some(file_state) = self.fetch_file_state(file) else {
            return Vec::new();
        };

        let source = file_state.source.as_str();
        if crate::analyzer::common::is_unparseable_source(source) {
            return Vec::new();
        }
        let mut parser = Self::build_parser(self.adapter.parser_language_for_file(file));
        let Some(tree) = parser.parse(source, None) else {
            return Vec::new();
        };
        let root = tree.root_node();

        // Walk the declared code-unit hierarchy to enumerate every function
        // in this file in source order (top-level + nested under classes /
        // modules / impls). Mirrors brokk-shared's
        // `functionCodeUnitsInFile`.
        let mut functions: Vec<CodeUnit> = Vec::new();
        let mut work: VecDeque<CodeUnit> =
            file_state.top_level_declarations.iter().cloned().collect();
        while let Some(cu) = work.pop_front() {
            if cu.is_function() {
                functions.push(cu.clone());
            }
            if let Some(children) = file_state.children.get(&cu) {
                for child in children {
                    work.push_back(child.clone());
                }
            }
        }

        let mut result = Vec::with_capacity(functions.len());
        for cu in functions {
            let Some(ranges) = file_state.ranges.get(&cu) else {
                continue;
            };
            let Some(primary) = ranges.first() else {
                continue;
            };
            // `descendant_for_byte_range(start, end)` returns the smallest
            // node fully containing `[start, end)`. With the analyzer's
            // primary range for the function this lands on the
            // function/method node itself, which is what the scorer wants
            // as its root.
            let Some(node) = root.descendant_for_byte_range(primary.start_byte, primary.end_byte)
            else {
                continue;
            };
            let complexity = cognitive_complexity::compute(node, source, config);
            result.push((cu, complexity));
        }
        result
    }

    fn get_skeleton(&self, code_unit: &CodeUnit) -> Option<String> {
        let mut rendered = String::new();
        self.render_skeleton_recursive(code_unit, "", false, &mut rendered);
        (!rendered.is_empty()).then(|| rendered.trim_end().to_string())
    }

    fn get_skeleton_header(&self, code_unit: &CodeUnit) -> Option<String> {
        let mut rendered = String::new();
        self.render_skeleton_recursive(code_unit, "", true, &mut rendered);
        (!rendered.is_empty()).then(|| rendered.trim_end().to_string())
    }

    fn get_source(&self, code_unit: &CodeUnit, include_comments: bool) -> Option<String> {
        let sources = self.get_sources(code_unit, include_comments);
        if sources.is_empty() {
            None
        } else {
            Some(sources.into_iter().collect::<Vec<_>>().join("\n\n"))
        }
    }

    fn get_sources(&self, code_unit: &CodeUnit, include_comments: bool) -> BTreeSet<String> {
        let mut ranges = if code_unit.is_function() {
            let mut grouped = Vec::new();
            for candidate in self.definitions(&code_unit.fq_name()) {
                if candidate.source() == code_unit.source() {
                    grouped.extend(self.ranges(&candidate));
                }
            }
            grouped
        } else {
            self.ranges(code_unit)
        };

        ranges.sort_by_key(|range| range.start_byte);
        ranges
            .into_iter()
            .filter_map(|range| self.source_slice(code_unit, &range, include_comments))
            .collect()
    }

    fn search_definitions(&self, pattern: &str, auto_quote: bool) -> BTreeSet<CodeUnit> {
        self.sql_search_definitions(pattern, auto_quote)
            .unwrap_or_default()
    }

    fn lookup_candidates_by_short_name(&self, symbol: &str) -> BTreeSet<CodeUnit> {
        self.sql_lookup_candidates_by_short_name(symbol)
            .unwrap_or_default()
    }

    fn lookup_candidates_by_identifier(&self, identifier: &str) -> BTreeSet<CodeUnit> {
        self.lookup_declarations_by_identifier(identifier)
    }

    fn search_symbol_candidates(
        &self,
        pattern: &str,
        auto_quote: bool,
    ) -> Vec<SearchSymbolCandidate> {
        self.sql_search_symbol_candidates(pattern, auto_quote)
            .unwrap_or_default()
    }

    fn metrics(&self) -> CodeBaseMetrics {
        CodeBaseMetrics::new(
            self.analyzed_live_files().len(),
            self.all_declarations().count(),
        )
    }

    fn contains_tests(&self, file: &ProjectFile) -> bool {
        self.fetch_file_state(file)
            .map(|state| state.contains_tests)
            .unwrap_or(false)
    }

    fn signatures(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.signatures_vec_of(code_unit)
    }

    fn signature_metadata(&self, code_unit: &CodeUnit) -> Vec<SignatureMetadata> {
        self.signature_metadata_vec_of(code_unit)
    }
}

/// A raw regex containing only ASCII identifier characters is exactly a
/// case-insensitive literal substring search. It is safe to use as a storage
/// candidate filter; all other regex forms retain the complete row set.
fn literal_ascii_search_substring(pattern: &str) -> Option<&str> {
    (!pattern.is_empty()
        && pattern
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'))
    .then_some(pattern)
}

/// Escape anchor metacharacters only where they form part of an identifier
/// token. A `$` directly followed by a word character (JS/PHP/Ruby sigils:
/// `$L`, `$utils`, `$global`) is unsatisfiable as an end-of-haystack anchor,
/// so escaping it cannot change any pattern that matches today; likewise a
/// `^` directly after a word character is unsatisfiable as a start anchor.
/// Intentional regex (groups, classes, real anchors) is left untouched.
fn escape_sigil_anchors(pattern: &str) -> String {
    let chars: Vec<char> = pattern.chars().collect();
    let mut escaped = String::with_capacity(pattern.len());
    for (index, ch) in chars.iter().enumerate() {
        let prev_is_word =
            index > 0 && (chars[index - 1].is_alphanumeric() || chars[index - 1] == '_');
        let next_is_word = chars
            .get(index + 1)
            .is_some_and(|next| next.is_alphanumeric() || *next == '_');
        let unsatisfiable = match ch {
            '$' => next_is_word,
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

fn enclosing_code_unit_rank(code_unit: &CodeUnit) -> usize {
    if code_unit.is_file_scope() { 1 } else { 0 }
}

fn node_range(node: Node<'_>) -> Range {
    Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row + 1,
        end_line: node.end_position().row + 1,
    }
}

/// Expand `start_byte` upward to include the declaration's own leading comment
/// block (its docstring / JSDoc / Rust attributes).
///
/// Only a comment block *contiguously attached* to the declaration counts: a
/// blank line terminates the walk. This is what keeps a file-level license
/// header — separated from the first declaration by a blank line — from being
/// misattributed as that declaration's docstring, which previously made chunk
/// `text` start at the file header while `start_line`/`end_line` still pointed
/// at the declaration body.
pub(crate) fn expanded_comment_start(source: &str, start_byte: usize) -> usize {
    let line_starts = compute_line_starts(source);
    let line_index = find_line_index_for_offset(&line_starts, start_byte);

    let mut comment_start = start_byte;
    for line_idx in (0..line_index).rev() {
        let line_start = line_starts[line_idx];
        let line_end = line_starts
            .get(line_idx + 1)
            .copied()
            .unwrap_or(source.len());
        let line = &source[line_start..line_end];
        let trimmed = line.trim_start();

        // A blank line separates the declaration (or its attached comment block)
        // from whatever precedes it; stop rather than reaching across the gap.
        if trimmed.trim().is_empty() {
            break;
        }

        if is_comment_like(trimmed) {
            comment_start = line_start;
            continue;
        }

        if let Some(offset) = first_comment_offset(line) {
            comment_start = line_start + offset;
        }
        break;
    }

    comment_start
}

fn is_comment_like(trimmed_line: &str) -> bool {
    trimmed_line.starts_with("/**")
        || trimmed_line.starts_with("/*")
        || trimmed_line.starts_with("*/")
        || trimmed_line.starts_with('*')
        || trimmed_line.starts_with("//")
        || trimmed_line.starts_with("#[")
}

fn first_comment_offset(line: &str) -> Option<usize> {
    ["/**", "/*", "//", "#["]
        .into_iter()
        .filter_map(|marker| line.find(marker))
        .min()
}

/// Walk `node` and append every `ERROR` / `MISSING` span into `out`. Does NOT
/// recurse into `ERROR` nodes: every descendant would also report as errored
/// and the diagnostic list would explode. Used both by `analyze_file` (to
/// populate the per-file cache) and by `lsp::handlers::diagnostic` (for the
/// fallback path when the analyzer has no cached state), so the two paths
/// share one source of truth for the walk semantics and the
/// `end_byte.max(start_byte)` clamp.
pub(crate) fn collect_parse_errors(node: Node, out: &mut Vec<crate::analyzer::ParseError>) {
    walk_tree_preorder(node, true, |node| {
        if node.is_error() || node.is_missing() {
            let range = Range {
                start_byte: node.start_byte(),
                end_byte: node.end_byte().max(node.start_byte()),
                start_line: node.start_position().row,
                end_line: node.end_position().row,
            };
            let kind = if node.is_missing() {
                crate::analyzer::ParseErrorKind::Missing(node.kind().to_string())
            } else {
                crate::analyzer::ParseErrorKind::Error
            };
            out.push(crate::analyzer::ParseError { range, kind });
            if node.is_error() {
                return WalkControl::SkipChildren;
            }
        }
        WalkControl::Continue
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::CodeUnitType;
    use crate::analyzer::go::GoAdapter;
    use crate::analyzer::java::JavaAdapter;
    use crate::analyzer::javascript::JavascriptAdapter;
    use crate::analyzer::python::PythonAdapter;
    use crate::analyzer::rust::RustAdapter;
    use crate::analyzer::store::AnalyzerStore;
    use crate::analyzer::typescript::TypescriptAdapter;
    use crate::analyzer::{
        AnalyzerConfig, IAnalyzer, JavaAnalyzer, Language, OverlayProject, TestProject,
    };
    use git2::{ObjectType, Oid};
    use std::path::{Path, PathBuf};
    use std::sync::{Barrier, Condvar, RwLock};

    #[derive(Clone)]
    struct CountingOverlayProject {
        delegate: TestProject,
        source: Arc<RwLock<(String, u64)>>,
        reads: Arc<AtomicUsize>,
    }

    impl CountingOverlayProject {
        fn new(root: impl Into<std::path::PathBuf>, source: impl Into<String>) -> Self {
            Self {
                delegate: TestProject::new(root, Language::Rust),
                source: Arc::new(RwLock::new((source.into(), 1))),
                reads: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn set_source(&self, source: impl Into<String>) {
            let mut current = self.source.write().expect("source lock poisoned");
            current.0 = source.into();
            current.1 = current
                .1
                .checked_add(1)
                .expect("test overlay revision space exhausted");
        }

        fn reset_reads(&self) {
            self.reads.store(0, Ordering::Relaxed);
        }

        fn read_count(&self) -> usize {
            self.reads.load(Ordering::Relaxed)
        }
    }

    impl Project for CountingOverlayProject {
        fn root(&self) -> &Path {
            self.delegate.root()
        }

        fn analyzer_languages(&self) -> BTreeSet<Language> {
            self.delegate.analyzer_languages()
        }

        fn all_files(&self) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.delegate.all_files()
        }

        fn analyzable_files(&self, language: Language) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.delegate.analyzable_files(language)
        }

        fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
            self.delegate.file_by_rel_path(rel_path)
        }

        fn read_source(&self, _file: &ProjectFile) -> std::io::Result<String> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            Ok(self.source.read().expect("source lock poisoned").0.clone())
        }

        fn read_source_snapshot(
            &self,
            _file: &ProjectFile,
        ) -> std::io::Result<ProjectSourceSnapshot> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            let current = self.source.read().expect("source lock poisoned");
            Ok(ProjectSourceSnapshot::overlay(
                current.0.clone(),
                OverlayRevision::from_monotonic_counter(current.1),
            ))
        }

        fn has_overlay(&self, _file: &ProjectFile) -> bool {
            true
        }
    }

    #[derive(Default)]
    struct OidRendezvousState {
        arrivals: usize,
    }

    #[derive(Clone)]
    struct RendezvousOverlayProject {
        delegate: TestProject,
        calls: Arc<AtomicUsize>,
        rendezvous: Arc<(Mutex<OidRendezvousState>, Condvar)>,
        timed_out: Arc<std::sync::atomic::AtomicBool>,
        fail_reads: bool,
    }

    impl Project for RendezvousOverlayProject {
        fn root(&self) -> &Path {
            self.delegate.root()
        }

        fn analyzer_languages(&self) -> BTreeSet<Language> {
            self.delegate.analyzer_languages()
        }

        fn all_files(&self) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.delegate.all_files()
        }

        fn analyzable_files(&self, language: Language) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.delegate.analyzable_files(language)
        }

        fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
            self.delegate.file_by_rel_path(rel_path)
        }

        fn read_source(&self, file: &ProjectFile) -> std::io::Result<String> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call < 2 {
                let (state, wake) = &*self.rendezvous;
                let mut state = state.lock().expect("OID rendezvous mutex poisoned");
                state.arrivals += 1;
                wake.notify_all();
                if state.arrivals < 2 {
                    let (new_state, timeout) = wake
                        .wait_timeout_while(state, Duration::from_secs(5), |state| {
                            state.arrivals < 2
                        })
                        .expect("OID rendezvous mutex poisoned");
                    state = new_state;
                    if timeout.timed_out() && state.arrivals < 2 {
                        self.timed_out.store(true, Ordering::SeqCst);
                        wake.notify_all();
                    }
                }
            }
            if self.fail_reads {
                if file.rel_path() == Path::new("src/First.java") {
                    std::thread::sleep(Duration::from_millis(50));
                }
                return Err(std::io::Error::other(format!(
                    "{} overlay OID failure",
                    file.rel_path().display()
                )));
            }
            self.delegate.read_source(file)
        }

        fn has_overlay(&self, _file: &ProjectFile) -> bool {
            true
        }
    }

    #[derive(Clone)]
    struct BlockingParseProject {
        delegate: TestProject,
        blocked_file: PathBuf,
        blocked_parse_started: std::sync::mpsc::SyncSender<()>,
        release: Arc<(Mutex<bool>, Condvar)>,
    }

    impl Project for BlockingParseProject {
        fn root(&self) -> &Path {
            self.delegate.root()
        }

        fn analyzer_languages(&self) -> BTreeSet<Language> {
            self.delegate.analyzer_languages()
        }

        fn all_files(&self) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.delegate.all_files()
        }

        fn analyzable_files(&self, language: Language) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.delegate.analyzable_files(language)
        }

        fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
            self.delegate.file_by_rel_path(rel_path)
        }

        fn read_source(&self, file: &ProjectFile) -> std::io::Result<String> {
            if file.rel_path() == self.blocked_file {
                self.blocked_parse_started
                    .send(())
                    .expect("blocked parse observer should remain connected");
                let (released, wake) = &*self.release;
                let mut released = released.lock().expect("parse release mutex poisoned");
                while !*released {
                    released = wake.wait(released).expect("parse release mutex poisoned");
                }
            }
            self.delegate.read_source(file)
        }
    }

    #[test]
    fn live_oid_resolution_hashes_two_overlays_concurrently() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let first = temp_file(&root, "src/First.java");
        first
            .write("package demo; class First {}\n")
            .expect("first Java source");
        let second = temp_file(&root, "src/Second.java");
        second
            .write("package demo; class Second {}\n")
            .expect("second Java source");

        let timed_out = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let project: Arc<dyn Project> = Arc::new(RendezvousOverlayProject {
            delegate: TestProject::new(&root, Language::Java),
            calls: Arc::new(AtomicUsize::new(0)),
            rendezvous: Arc::new((Mutex::new(OidRendezvousState::default()), Condvar::new())),
            timed_out: Arc::clone(&timed_out),
            fail_reads: false,
        });

        let analyzer = TreeSitterAnalyzer::new_with_config(
            project,
            JavaAdapter,
            AnalyzerConfig {
                parallelism: Some(2),
                ..AnalyzerConfig::default()
            },
        );

        assert!(
            !timed_out.load(Ordering::SeqCst),
            "both overlay OID reads should rendezvous before the deadlock guard releases either one"
        );
        for (file, expected) in [(&first, "First"), (&second, "Second")] {
            assert!(
                analyzer
                    .get_declarations(file)
                    .iter()
                    .any(|declaration| declaration.short_name() == expected),
                "real reconcile should retain the {expected} declaration"
            );
        }
    }

    #[test]
    fn live_oid_resolution_reports_first_input_error_after_parallel_planning() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let first = temp_file(&root, "src/First.java");
        first.write("first\n").expect("first source");
        let expected_first_error = format!("{} overlay OID failure", first.rel_path().display());
        let second = temp_file(&root, "src/Second.java");
        second.write("second\n").expect("second source");

        let timed_out = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let project = RendezvousOverlayProject {
            delegate: TestProject::new(&root, Language::Java),
            calls: Arc::new(AtomicUsize::new(0)),
            rendezvous: Arc::new((Mutex::new(OidRendezvousState::default()), Condvar::new())),
            timed_out: Arc::clone(&timed_out),
            fail_reads: true,
        };
        let store_context = default_store_context(&project);

        let error = TreeSitterAnalyzer::<JavaAdapter>::resolve_live_oids(
            &project,
            &[first, second],
            &AnalyzerConfig {
                parallelism: Some(2),
                ..AnalyzerConfig::default()
            },
            &store_context,
            true,
        )
        .expect_err("both overlay reads fail");

        assert!(
            !timed_out.load(Ordering::SeqCst),
            "the error-order test should exercise concurrent planning"
        );
        assert_eq!(error, expected_first_error);
    }

    #[test]
    fn empty_live_oid_planning_preserves_refresh_and_replace_semantics() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/Existing.java");
        let source = "package demo; class Existing {}\n";
        file.write(source).expect("existing Java source");
        let project = TestProject::new(&root, Language::Java);
        let store_context = default_store_context(&project);
        let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).expect("source OID");
        store_context
            .live_paths
            .refresh([LivePathEntry::overlay(file.clone(), oid)]);
        let config = AnalyzerConfig {
            parallelism: Some(2),
            ..AnalyzerConfig::default()
        };

        let refreshed = TreeSitterAnalyzer::<JavaAdapter>::resolve_live_oids(
            &project,
            &[],
            &config,
            &store_context,
            false,
        )
        .expect("empty refresh");
        assert!(refreshed.is_empty());
        assert_eq!(
            store_context.live_paths.snapshot().oid_for_path(&file),
            Some(oid)
        );

        let replaced = TreeSitterAnalyzer::<JavaAdapter>::resolve_live_oids(
            &project,
            &[],
            &config,
            &store_context,
            true,
        )
        .expect("empty replacement");
        assert!(replaced.is_empty());
        assert_eq!(
            store_context.live_paths.snapshot().oid_for_path(&file),
            None
        );
    }

    #[test]
    fn persisted_epoch_publication_failure_is_returned_from_analyzer_construction() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let db = root.join("analyzer.db");
        drop(AnalyzerStore::open_persistent(&db).expect("initialize persistent store"));
        let conn = crate::cache_db::open_unified_connection(&db).expect("open test connection");
        conn.execute_batch(
            "CREATE TRIGGER fail_epoch_publication
             BEFORE INSERT ON analysis_epochs
             BEGIN
                 SELECT RAISE(FAIL, 'forced epoch publication failure');
             END;",
        )
        .expect("install epoch failure trigger");
        drop(conn);

        let project: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::Java));
        let store_context = AnalyzerStoreContext {
            store: Arc::new(AnalyzerStore::open_persistent(&db).expect("reopen persistent store")),
            gc: Arc::new(crate::analyzer::store::gc::AnalyzerGcCoordinator::default()),
            liveness: None,
            live_paths: Arc::new(LivePathMap::default()),
            generations: Arc::new(HashMap::default()),
        };

        let error = match TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            project,
            JavaAdapter,
            AnalyzerConfig::default(),
            store_context,
            None,
        ) {
            Ok(_) => panic!("epoch publication failure should be returned"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("publishing analyzer epochs"));
        assert!(
            error
                .to_string()
                .contains("forced epoch publication failure")
        );
    }

    #[test]
    fn reconcile_persists_fast_parse_before_blocked_slow_parse_is_released() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let fast = temp_file(&root, "src/Fast.java");
        fast.write("package demo; class Fast {}\n")
            .expect("fast Java source");
        let slow = temp_file(&root, "src/Slow.java");
        slow.write("package demo; class Slow {}\n")
            .expect("slow Java source");

        let (blocked_parse_started_tx, blocked_parse_started_rx) = std::sync::mpsc::sync_channel(1);
        let (persisted_tx, persisted_rx) = std::sync::mpsc::sync_channel(1);
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let project: Arc<dyn Project> = Arc::new(BlockingParseProject {
            delegate: TestProject::new(&root, Language::Java),
            blocked_file: slow.rel_path().to_path_buf(),
            blocked_parse_started: blocked_parse_started_tx,
            release: Arc::clone(&release),
        });
        let store_context = default_store_context(project.as_ref());
        let store = Arc::clone(&store_context.store);
        let progress: BuildProgress = Arc::new(move |event| {
            if event.phase == BuildProgressPhase::Persist && event.completed > 0 {
                let _ = persisted_tx.try_send(());
            }
        });

        let build = std::thread::spawn(move || {
            TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
                project,
                JavaAdapter,
                AnalyzerConfig {
                    parallelism: Some(2),
                    ..AnalyzerConfig::default()
                },
                store_context,
                Some(progress),
            )
        });

        blocked_parse_started_rx
            .recv()
            .expect("slow parse should reach the injected block");
        persisted_rx
            .recv()
            .expect("fast parse should persist while slow parse is blocked");
        let persistence_starts_before_release = store.parsed_blob_transaction_starts_for_test();
        {
            let (released, wake) = &*release;
            *released.lock().expect("parse release mutex poisoned") = true;
            wake.notify_all();
        }
        build
            .join()
            .expect("analyzer build should finish")
            .expect("analyzer epochs should initialize");

        assert!(
            persistence_starts_before_release > 0,
            "the real reconcile pipeline should start persisting the prepared fast blob while the unrelated slow parser remains blocked"
        );
    }

    #[test]
    fn reconcile_batches_257_small_files_into_five_transactions() {
        const FILES: usize = 257;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        for index in 0..FILES {
            let file = temp_file(&root, &format!("src/Type{index}.java"));
            file.write(format!("package demo; class Type{index} {{}}\n"))
                .expect("Java source");
        }
        let project: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::Java));
        let store_context = default_store_context(project.as_ref());
        let store = Arc::clone(&store_context.store);

        let analyzer = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            project,
            JavaAdapter,
            AnalyzerConfig {
                parallelism: Some(1),
                ..AnalyzerConfig::default()
            },
            store_context,
            None,
        )
        .expect("analyzer epochs should initialize");

        assert_eq!(store.parsed_blob_transaction_starts_for_test(), 5);
        assert_eq!(analyzer.state.persistence_stats.transactions, 5);
        assert_eq!(analyzer.state.persistence_stats.committed_blobs, FILES);
        assert_eq!(analyzer.state.persistence_stats.failed_blobs, 0);
        assert!(analyzer.state.persistence_stats.peak_in_flight_items > 0);
        assert!(
            analyzer.state.persistence_stats.peak_in_flight_items
                <= analyzer
                    .state
                    .persistence_stats
                    .configured_max_in_flight_items
        );
        assert!(
            analyzer
                .state
                .persistence_stats
                .peak_in_flight_payload_bytes
                > 0
        );
    }

    #[test]
    fn preparation_failure_reaches_terminal_persist_progress_and_dirty_fallback() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        for name in ["GoodA", "Bad", "GoodB"] {
            let file = temp_file(&root, &format!("src/{name}.java"));
            file.write(format!("package demo; class {name} {{}}\n"))
                .expect("Java source");
        }
        let bad = ProjectFile::new(root.clone(), "src/Bad.java");
        *PREPARATION_FAILURE_PATH
            .lock()
            .expect("preparation failure path mutex poisoned") = Some(bad.abs_path().to_path_buf());
        let project: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::Java));
        let store_context = default_store_context(project.as_ref());
        let events = Arc::new(Mutex::new(Vec::new()));
        let progress_events = Arc::clone(&events);
        let progress: BuildProgress = Arc::new(move |event| {
            progress_events
                .lock()
                .expect("progress event mutex poisoned")
                .push(event);
        });

        let analyzer = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            project,
            JavaAdapter,
            AnalyzerConfig {
                parallelism: Some(1),
                ..AnalyzerConfig::default()
            },
            store_context,
            Some(progress),
        )
        .expect("analyzer epochs should initialize");
        *PREPARATION_FAILURE_PATH
            .lock()
            .expect("preparation failure path mutex poisoned") = None;

        assert_eq!(analyzer.state.persistence_stats.committed_blobs, 2);
        assert_eq!(analyzer.state.persistence_stats.failed_blobs, 1);
        let dirty = analyzer.state.dirty_snapshot();
        assert_eq!(dirty.len(), 1);
        assert_eq!(dirty.keys().next().unwrap().rel_path, bad.rel_path());
        let events = events.lock().expect("progress event mutex poisoned");
        let final_persist = events
            .iter()
            .rev()
            .find(|event| event.phase == BuildProgressPhase::Persist)
            .expect("persist progress event");
        assert_eq!(final_persist.completed, 3);
        assert_eq!(final_persist.total, 3);
    }

    #[test]
    fn reconcile_keeps_only_irreducible_prepared_failure_dirty() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let good_a = temp_file(&root, "src/GoodA.java");
        good_a
            .write("package demo; class GoodA {}\n")
            .expect("good Java source");
        let bad = temp_file(&root, "src/Bad.java");
        bad.write("package demo; class Bad {}\n")
            .expect("bad Java source");
        let good_b = temp_file(&root, "src/GoodB.java");
        good_b
            .write("package demo; class GoodB {}\n")
            .expect("good Java source");
        *PREPARED_FAILURE_PATH
            .lock()
            .expect("prepared failure path mutex poisoned") = Some(bad.abs_path().to_path_buf());

        let project: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::Java));
        let analyzer = TreeSitterAnalyzer::new_with_config(
            project,
            JavaAdapter,
            AnalyzerConfig {
                parallelism: Some(3),
                ..AnalyzerConfig::default()
            },
        );
        *PREPARED_FAILURE_PATH
            .lock()
            .expect("prepared failure path mutex poisoned") = None;

        let dirty = analyzer.state.dirty_snapshot();
        assert_eq!(dirty.len(), 1);
        let (dirty_key, dirty_state) = dirty.iter().next().unwrap();
        assert_eq!(dirty_key.rel_path, bad.rel_path());
        assert_eq!(dirty_state.attempts, STORE_WRITE_IMMEDIATE_RETRIES + 1);
        for file in [&good_a, &good_b] {
            let source = file.read_to_string().unwrap();
            let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).unwrap();
            assert!(
                analyzer
                    .store_context
                    .store
                    .contains_parsed_blob(oid, "java")
                    .unwrap()
            );
        }
        let bad_oid =
            Oid::hash_object(ObjectType::Blob, bad.read_to_string().unwrap().as_bytes()).unwrap();
        assert!(
            !analyzer
                .store_context
                .store
                .contains_parsed_blob(bad_oid, "java")
                .unwrap()
        );
    }

    fn parse_javascript(source: &str) -> Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .expect("javascript parser");
        parser.parse(source, None).expect("parse javascript")
    }

    fn empty_file_state(source: impl Into<String>, contains_tests: bool) -> FileState {
        FileState {
            source: source.into(),
            package_name: String::new(),
            content_qualifier: String::new(),
            top_level_declarations: Vec::new(),
            declarations: HashSet::default(),
            definition_lookup_units: HashSet::default(),
            import_statements: Vec::new(),
            imports: Vec::new(),
            scala_exports: HashMap::default(),
            raw_supertypes: HashMap::default(),
            supertype_lookup_paths: HashMap::default(),
            type_identifiers: HashSet::default(),
            signatures: HashMap::default(),
            signature_metadata: HashMap::default(),
            cpp_template_metadata: HashMap::default(),
            ruby_method_dispatch_modes: HashMap::default(),
            ranges: HashMap::default(),
            children: HashMap::default(),
            scala_traits: HashSet::default(),
            type_aliases: HashSet::default(),
            contains_tests,
            parse_errors: None,
        }
    }

    fn temp_file(root: &Path, rel_path: &str) -> ProjectFile {
        ProjectFile::new(root.to_path_buf(), rel_path)
    }

    fn test_range(start_byte: usize) -> Range {
        Range {
            start_byte,
            end_byte: start_byte + 1,
            start_line: 0,
            end_line: 0,
        }
    }

    #[test]
    fn declaration_identity_multiset_survives_replace_until_last_exact_removal() {
        let file = ProjectFile::new(std::env::temp_dir(), "identity.cpp");
        let first = CodeUnit::with_signature(
            file.clone(),
            CodeUnitType::Function,
            "pkg",
            "overloaded",
            Some("(int)".to_string()),
            false,
        );
        let synthetic_variant = CodeUnit::with_signature(
            file.clone(),
            CodeUnitType::Function,
            "pkg",
            "overloaded",
            Some("(double)".to_string()),
            true,
        );
        let identity_probe =
            CodeUnit::new(file.clone(), CodeUnitType::Function, "pkg", "overloaded");
        let mut parsed = ParsedFile::new(String::new());
        parsed.add_code_unit_with_range(first.clone(), test_range(0), None, None);
        parsed.add_synthetic_code_unit(synthetic_variant.clone(), None, None);
        assert!(parsed.contains_declaration_identity(&identity_probe));
        assert_eq!(
            Some(&2),
            parsed
                .declaration_identities
                .get(&DeclarationIdentity(identity_probe.clone()))
        );

        let tree = parse_javascript("const replacement = 1;");
        let node = tree.root_node().named_child(0).expect("replacement node");
        parsed.replace_code_unit(first.clone(), node, "const replacement = 1;", None, None);
        assert_eq!(
            Some(&2),
            parsed
                .declaration_identities
                .get(&DeclarationIdentity(identity_probe.clone()))
        );

        parsed.remove_code_unit(&first);
        assert!(parsed.contains_declaration_identity(&identity_probe));
        assert_eq!(
            Some(&1),
            parsed
                .declaration_identities
                .get(&DeclarationIdentity(identity_probe.clone()))
        );
        parsed.remove_code_unit(&synthetic_variant);
        assert!(!parsed.contains_declaration_identity(&identity_probe));
    }

    #[test]
    fn declaration_identity_index_tracks_file_scope_and_recursive_removal() {
        let file = ProjectFile::new(std::env::temp_dir(), "recursive.cpp");
        let mut parsed = ParsedFile::new(String::new());
        let file_scope = CodeUnit::file_scope(file.clone());
        parsed.add_file_scope(&file, "int value;\n");
        parsed.add_file_scope(&file, "int value;\n");
        assert_eq!(
            Some(&1),
            parsed
                .declaration_identities
                .get(&DeclarationIdentity(file_scope.clone()))
        );
        parsed.remove_code_unit(&file_scope);
        assert!(!parsed.contains_declaration_identity(&file_scope));

        let parent = CodeUnit::new(file.clone(), CodeUnitType::Class, "", "Parent");
        let child_one = CodeUnit::with_signature(
            file.clone(),
            CodeUnitType::Function,
            "Parent",
            "child",
            Some("(int)".to_string()),
            false,
        );
        let child_two = CodeUnit::with_signature(
            file,
            CodeUnitType::Function,
            "Parent",
            "child",
            Some("(double)".to_string()),
            true,
        );
        let child_identity = CodeUnit::new(
            child_one.source().clone(),
            CodeUnitType::Function,
            "Parent",
            "child",
        );
        parsed.add_code_unit_with_range(parent.clone(), test_range(1), None, None);
        parsed.add_code_unit_with_range(child_one, test_range(2), Some(parent.clone()), None);
        parsed.add_synthetic_code_unit(child_two, Some(parent.clone()), None);
        assert_eq!(
            Some(&2),
            parsed
                .declaration_identities
                .get(&DeclarationIdentity(child_identity.clone()))
        );

        parsed.remove_code_unit(&parent);
        assert!(!parsed.contains_declaration_identity(&parent));
        assert!(!parsed.contains_declaration_identity(&child_identity));
    }

    #[test]
    fn tree_preorder_walk_preserves_source_order_without_recursion() {
        let tree = parse_javascript("const first = 1; function second() { return first; }\n");
        let mut declarations = Vec::new();

        walk_named_tree_preorder(tree.root_node(), false, |node| {
            if matches!(node.kind(), "lexical_declaration" | "function_declaration") {
                declarations.push(node.kind().to_string());
            }
            WalkControl::Continue
        });

        assert_eq!(
            declarations,
            vec!["lexical_declaration", "function_declaration"]
        );
    }

    #[test]
    fn parse_error_collection_skips_error_descendants_iteratively() {
        let tree = parse_javascript("function broken( { const value = ; }\n");
        let mut errors = Vec::new();

        collect_parse_errors(tree.root_node(), &mut errors);

        assert!(!errors.is_empty(), "expected parse errors");
        for index in 0..errors.len() {
            for other in 0..errors.len() {
                if index == other {
                    continue;
                }
                let left = &errors[index].range;
                let right = &errors[other].range;
                assert!(
                    !(left.start_byte <= right.start_byte
                        && right.end_byte <= left.end_byte
                        && (left.start_byte, left.end_byte) != (right.start_byte, right.end_byte)),
                    "error descendant should have been skipped: {errors:?}"
                );
            }
        }
    }

    #[test]
    fn dirty_file_state_is_authoritative_for_symbol_reads() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("pkg")).unwrap();
        let source = "class Dirty:\n    pass\n".to_string();
        std::fs::write(root.join("pkg/dirty.py"), &source).unwrap();
        let file = ProjectFile::new(root.clone(), "pkg/dirty.py");
        let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).unwrap();

        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Python));
        let adapter = Arc::new(PythonAdapter);
        let mut parser = TreeSitterAnalyzer::<PythonAdapter>::build_parser(
            adapter.parser_language_for_file(&file),
        );
        let parsed = TreeSitterAnalyzer::<PythonAdapter>::analyze_source(
            &mut parser,
            &*adapter,
            &file,
            source,
        )
        .expect("python file parses");
        let key = TreeSitterAnalyzer::<PythonAdapter>::transient_cache_key(oid, &file);
        let mut dirty = HashMap::default();
        dirty.insert(
            key,
            TreeSitterAnalyzer::<PythonAdapter>::dirty_file_state(
                Arc::new(parsed),
                GenerationId::BOOTSTRAP,
                32,
                "forced test persistence failure".to_string(),
                false,
            ),
        );

        let live_paths = Arc::new(LivePathMap::default());
        live_paths.refresh([LivePathEntry::overlay(file.clone(), oid)]);
        let store = Arc::new(AnalyzerStore::open_in_memory().unwrap());
        let store_context = AnalyzerStoreContext {
            store: Arc::clone(&store),
            gc: Arc::new(crate::analyzer::store::gc::AnalyzerGcCoordinator::default()),
            liveness: None,
            live_paths,
            generations: Arc::new(HashMap::from_iter([(
                "python".to_string(),
                GenerationId::BOOTSTRAP,
            )])),
        };
        let config = AnalyzerConfig::default();
        let analyzer = TreeSitterAnalyzer::from_state(
            project,
            adapter,
            config.clone(),
            AnalyzerRuntimeState::new(HashMap::default(), dirty, HashMap::default(), Vec::new()),
            Arc::new(TreeSitterAnalyzer::<PythonAdapter>::build_structural_cache(
                &config,
            )),
            crate::analyzer::semantic::service::CompleteSemanticArtifactCache::new(
                config.memo_cache_budget_bytes() / 8,
            ),
            store_context,
        );

        assert!(!store.contains_parsed_blob(oid, "python").unwrap());
        assert!(
            analyzer
                .declarations(&file)
                .iter()
                .any(|unit| unit.fq_name() == "pkg.dirty.Dirty")
        );
        assert_eq!(analyzer.get_definitions("pkg.dirty.Dirty").len(), 1);
        assert!(
            analyzer
                .lookup_declarations_by_identifier("Dirty")
                .iter()
                .any(|unit| unit.fq_name() == "pkg.dirty.Dirty"),
            "exact identifier candidates must include dirty declarations"
        );
        assert!(
            analyzer
                .lookup_declarations_by_identifier("dirty")
                .iter()
                .any(|unit| unit.is_module() && unit.fq_name() == "pkg.dirty"),
            "exact identifier candidates must retain non-persisted path modules"
        );
    }

    #[test]
    fn terminal_stale_dirty_state_remains_authoritative_without_retrying() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let source = "class Dirty:\n    pass\n";
        std::fs::write(root.join("dirty.py"), source).unwrap();
        let file = ProjectFile::new(root.clone(), "dirty.py");
        let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Python));
        let analyzer = TreeSitterAnalyzer::new(project, PythonAdapter);
        let mut parser = TreeSitterAnalyzer::<PythonAdapter>::build_parser(
            analyzer.adapter.parser_language_for_file(&file),
        );
        let parsed = TreeSitterAnalyzer::<PythonAdapter>::analyze_source(
            &mut parser,
            analyzer.adapter.as_ref(),
            &file,
            source.to_string(),
        )
        .unwrap();
        let key = TreeSitterAnalyzer::<PythonAdapter>::transient_cache_key(oid, &file);
        let generation = analyzer.store_context.generations["python"];
        analyzer
            .store_context
            .store
            .ensure_language_epoch_value("python", "cutover-after-failure")
            .unwrap();
        analyzer.state.dirty_file_states.lock().unwrap().insert(
            key.clone(),
            TreeSitterAnalyzer::<PythonAdapter>::dirty_file_state(
                Arc::new(parsed),
                generation,
                STORE_WRITE_IMMEDIATE_RETRIES + 1,
                "stale generation".to_string(),
                true,
            ),
        );
        let starts = analyzer
            .store_context
            .store
            .parsed_blob_transaction_starts_for_test();

        let state = analyzer.retry_dirty_file_state(&key, "python").unwrap();

        assert!(
            state
                .declarations
                .iter()
                .any(|unit| unit.short_name() == "Dirty")
        );
        assert_eq!(
            analyzer
                .store_context
                .store
                .parsed_blob_transaction_starts_for_test(),
            starts,
            "terminal stale state must not schedule another obsolete write"
        );
        assert!(
            analyzer
                .state
                .dirty_file_states
                .lock()
                .unwrap()
                .get(&key)
                .unwrap()
                .terminal_stale
        );
    }

    #[test]
    fn dirty_path_projection_is_authoritative_for_exact_module_lookup() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("pkg")).unwrap();
        let source = "def helper():\n    pass\n";
        std::fs::write(root.join("pkg/util.py"), source).unwrap();
        let file = ProjectFile::new(root.clone(), "pkg/util.py");
        let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).unwrap();
        let adapter = Arc::new(PythonAdapter);
        let row = TreeSitterAnalyzer::<PythonAdapter>::path_symbol_row(&*adapter, &file, oid)
            .expect("python path projection");
        let mut dirty_path_symbol_rows = HashMap::default();
        dirty_path_symbol_rows.insert(file.clone(), ("python".to_string(), row));

        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Python));
        let live_paths = Arc::new(LivePathMap::default());
        live_paths.refresh([LivePathEntry::overlay(file.clone(), oid)]);
        let store_context = AnalyzerStoreContext {
            store: Arc::new(AnalyzerStore::open_in_memory().unwrap()),
            gc: Arc::new(crate::analyzer::store::gc::AnalyzerGcCoordinator::default()),
            liveness: None,
            live_paths,
            generations: Arc::new(HashMap::from_iter([(
                "python".to_string(),
                GenerationId::BOOTSTRAP,
            )])),
        };
        let config = AnalyzerConfig::default();
        let analyzer = TreeSitterAnalyzer::from_state(
            project,
            adapter,
            config.clone(),
            AnalyzerRuntimeState::new(
                HashMap::default(),
                HashMap::default(),
                dirty_path_symbol_rows,
                Vec::new(),
            ),
            Arc::new(TreeSitterAnalyzer::<PythonAdapter>::build_structural_cache(
                &config,
            )),
            crate::analyzer::semantic::service::CompleteSemanticArtifactCache::new(
                config.memo_cache_budget_bytes() / 8,
            ),
            store_context,
        );

        assert_eq!(
            analyzer
                .get_definitions("pkg.util")
                .into_iter()
                .map(|unit| unit.fq_name())
                .collect::<Vec<_>>(),
            vec!["pkg.util".to_string()]
        );
    }

    #[test]
    fn dirty_file_state_is_authoritative_for_bulk_reads() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("pkg")).unwrap();
        let source = "import os\nclass Dirty:\n    pass\n".to_string();
        std::fs::write(root.join("pkg/dirty.py"), &source).unwrap();
        let file = ProjectFile::new(root.clone(), "pkg/dirty.py");
        let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).unwrap();

        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Python));
        let adapter = Arc::new(PythonAdapter);
        let mut parser = TreeSitterAnalyzer::<PythonAdapter>::build_parser(
            adapter.parser_language_for_file(&file),
        );
        let parsed = TreeSitterAnalyzer::<PythonAdapter>::analyze_source(
            &mut parser,
            &*adapter,
            &file,
            source,
        )
        .expect("python file parses");
        let key = TreeSitterAnalyzer::<PythonAdapter>::transient_cache_key(oid, &file);
        let mut dirty = HashMap::default();
        dirty.insert(
            key,
            TreeSitterAnalyzer::<PythonAdapter>::dirty_file_state(
                Arc::new(parsed),
                GenerationId::BOOTSTRAP,
                32,
                "forced test persistence failure".to_string(),
                false,
            ),
        );

        let live_paths = Arc::new(LivePathMap::default());
        live_paths.refresh([LivePathEntry::overlay(file.clone(), oid)]);
        let store = Arc::new(AnalyzerStore::open_in_memory().unwrap());
        let store_context = AnalyzerStoreContext {
            store: Arc::clone(&store),
            gc: Arc::new(crate::analyzer::store::gc::AnalyzerGcCoordinator::default()),
            liveness: None,
            live_paths,
            generations: Arc::new(HashMap::from_iter([(
                "python".to_string(),
                GenerationId::BOOTSTRAP,
            )])),
        };
        let config = AnalyzerConfig::default();
        let analyzer = TreeSitterAnalyzer::from_state(
            project,
            adapter,
            config.clone(),
            AnalyzerRuntimeState::new(HashMap::default(), dirty, HashMap::default(), Vec::new()),
            Arc::new(TreeSitterAnalyzer::<PythonAdapter>::build_structural_cache(
                &config,
            )),
            crate::analyzer::semantic::service::CompleteSemanticArtifactCache::new(
                config.memo_cache_budget_bytes() / 8,
            ),
            store_context,
        );

        assert!(!store.contains_parsed_blob(oid, "python").unwrap());
        let states = analyzer.bulk_file_states([file.clone()], BulkFileStateSource::Omit);
        assert!(states.get(&file).is_some_and(|state| {
            state
                .declarations
                .iter()
                .any(|unit| unit.fq_name() == "pkg.dirty.Dirty")
        }));
        let imports = analyzer.bulk_import_infos([file.clone()]);
        assert_eq!(
            imports
                .get(&file)
                .and_then(|imports| imports.first())
                .and_then(|import| import.identifier.as_deref()),
            Some("os")
        );
    }

    #[test]
    fn storage_adapter_identity_defaults_preserve_in_memory_facts() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/Service.java");
        let adapter = JavaAdapter;
        let unit = CodeUnit::new(file.clone(), CodeUnitType::Class, "example", "Service");
        let mut state = empty_file_state("class Service {}\n", true);
        state.declarations.insert(unit.clone());
        let before = state.clone();

        assert_eq!(adapter.storage_language_key_for_file(&file), "java");
        assert_eq!(adapter.storage_language_keys().len(), 1);
        assert_eq!(
            adapter.storage_content_qualifier(&unit, "example"),
            "example"
        );
        assert_eq!(adapter.storage_file_content_qualifier("example"), "example");
        assert_eq!(
            adapter.hydrate_content_qualifier("example", &file),
            "example"
        );
        assert!(adapter.should_persist_code_unit(&unit));
        assert!(!adapter.should_persist_code_unit(&CodeUnit::file_scope(file.clone())));
        assert!(adapter.storage_contains_tests(&state));
        assert!(adapter.hydrate_contains_tests(true, &file, &state.source));

        let source = state.source.clone();
        adapter.synthesize_hydrated_units(&file, &source, &mut state);
        assert_eq!(state.declarations, before.declarations);
        assert_eq!(state.top_level_declarations, before.top_level_declarations);
        assert_eq!(state.ranges, before.ranges);
    }

    #[test]
    fn storage_adapter_path_qualifiers_reconstruct_workspace_identity() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");

        let python_file = temp_file(&root, "pkg/service.py");
        python_file.write("class Service:\n    pass\n").unwrap();
        let python = PythonAdapter;
        let python_unit = CodeUnit::new(
            python_file.clone(),
            CodeUnitType::Class,
            "pkg.service",
            "Service",
        );
        assert_eq!(python.storage_content_qualifier(&python_unit, ""), "");
        assert_eq!(python.storage_file_content_qualifier("pkg.service"), "");
        assert_eq!(
            python.hydrate_content_qualifier("", &python_file),
            "pkg.service"
        );

        let rust_file = temp_file(&root, "src/net/mod.rs");
        let rust = RustAdapter;
        let rust_unit = CodeUnit::new(rust_file.clone(), CodeUnitType::Class, "net", "Client");
        assert_eq!(rust.storage_content_qualifier(&rust_unit, ""), "");
        assert_eq!(rust.hydrate_content_qualifier("", &rust_file), "net");
        let rust_impl_member = CodeUnit::with_signature(
            rust_file.clone(),
            CodeUnitType::Function,
            "model",
            "Writer.write",
            Some("impl Writer::fn write(&self) { ... }".to_string()),
            false,
        );
        assert_eq!(
            rust.storage_content_qualifier(&rust_impl_member, "net"),
            "model"
        );
        assert_eq!(rust.hydrate_content_qualifier("model", &rust_file), "model");
        let local_rust_impl_member = CodeUnit::with_signature(
            rust_file.clone(),
            CodeUnitType::Function,
            "net",
            "Client.connect",
            Some("impl Client::fn connect(&self) { ... }".to_string()),
            false,
        );
        assert_eq!(
            rust.storage_content_qualifier(&local_rust_impl_member, "net"),
            ""
        );

        std::fs::write(root.join("go.mod"), "module example.com/demo\n").unwrap();
        let go_file = temp_file(&root, "internal/service/service.go");
        go_file
            .write("package service\n\ntype Service struct{}\n")
            .unwrap();
        let go = GoAdapter;
        let go_unit = CodeUnit::new(
            go_file.clone(),
            CodeUnitType::Class,
            "example.com/demo/internal/service",
            "Service",
        );
        assert_eq!(go.storage_content_qualifier(&go_unit, "service"), "service");
        assert_eq!(
            go.hydrate_content_qualifier("", &go_file),
            "example.com/demo/internal/service"
        );
    }

    #[test]
    fn storage_adapter_path_units_and_tests_reconstruct_after_hydration() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let tsx_file = temp_file(&root, "src/widget.test.tsx");
        let source = "import { value } from './value';\ntest('value', () => value());\n";
        let adapter = TypescriptAdapter;

        assert_eq!(
            adapter.storage_language_key_for_file(&tsx_file),
            "typescript:tsx"
        );
        assert_eq!(
            adapter
                .storage_language_keys()
                .into_iter()
                .map(|(key, _)| key)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["typescript:ts".to_string(), "typescript:tsx".to_string()])
        );

        let mut state = empty_file_state(source, true);
        state.imports.push(ImportInfo {
            raw_snippet: "import { value } from './value';".to_string(),
            is_wildcard: false,
            identifier: Some("value".to_string()),
            alias: None,
            path: None,
        });
        assert!(adapter.storage_contains_tests(&state));
        assert!(adapter.hydrate_contains_tests(false, &tsx_file, ""));

        adapter.synthesize_hydrated_units(&tsx_file, source, &mut state);
        let module = state
            .top_level_declarations
            .iter()
            .find(|unit| unit.is_module())
            .expect("synthetic TypeScript module");
        assert!(!adapter.should_persist_code_unit(module));
        assert!(state.declarations.contains(module));
        assert_eq!(state.ranges.get(module).map(Vec::len), Some(1));

        let js_file = temp_file(&root, "src/widget.spec.js");
        let javascript = JavascriptAdapter;
        assert!(javascript.hydrate_contains_tests(false, &js_file, ""));
        let mut js_state = empty_file_state(source, true);
        js_state.imports = state.imports.clone();
        javascript.synthesize_hydrated_units(&js_file, source, &mut js_state);
        let js_module = js_state
            .top_level_declarations
            .iter()
            .find(|unit| unit.is_module())
            .expect("synthetic JavaScript module");
        assert!(!javascript.should_persist_code_unit(js_module));
        assert!(js_state.declarations.contains(js_module));
        assert_eq!(js_state.ranges.get(js_module).map(Vec::len), Some(1));
    }

    #[test]
    fn storage_adapter_python_synthesizes_path_module_and_children() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "pkg/service.py");
        let source = "class Service:\n    pass\n";
        let class = CodeUnit::new(file.clone(), CodeUnitType::Class, "pkg.service", "Service");
        let mut state = empty_file_state(source, false);
        state.top_level_declarations.push(class.clone());
        state.declarations.insert(class.clone());

        let adapter = PythonAdapter;
        adapter.synthesize_hydrated_units(&file, source, &mut state);
        let module = state
            .top_level_declarations
            .first()
            .expect("synthetic Python module");
        assert!(module.is_module());
        assert_eq!(module.fq_name(), "pkg.service");
        assert!(!adapter.should_persist_code_unit(module));
        assert_eq!(state.children.get(module), Some(&vec![class]));
        assert_eq!(state.ranges.get(module).map(Vec::len), Some(1));
    }

    #[test]
    fn usage_facts_index_uses_persisted_projection_without_file_hydration() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        std::fs::create_dir_all(root.join("src")).expect("source directory");

        for index in 0..=TRANSIENT_FILE_STATE_CACHE_CAPACITY {
            std::fs::write(
                root.join(format!("src/Type{index}.java")),
                format!(
                    "package demo; public class Type{index} {{ public String value{index}() {{ return \"\"; }} }}\n"
                ),
            )
            .expect("java source");
        }

        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Java));
        let analyzer = TreeSitterAnalyzer::new(project, JavaAdapter);
        analyzer.reset_full_hydration_count_for_test();

        let facts = analyzer.usage_facts_index();

        assert!(
            !facts.facts("demo.Type0.value0").is_empty(),
            "usage facts should include persisted Java methods"
        );
        assert_eq!(analyzer.full_hydration_count_for_test(), 0);
        assert_eq!(analyzer.bulk_hydration_count_for_test(), 0);
    }

    #[test]
    fn stale_lazy_index_builds_return_fallback_without_poisoning_once_locks() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        std::fs::write(root.join("Model.java"), "class Model {}\n").unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Java));
        let analyzer = TreeSitterAnalyzer::new(project, JavaAdapter);
        analyzer
            .store_context
            .store
            .ensure_language_epoch_value("java", "cutover-before-lazy-read")
            .unwrap();
        let context = Arc::new(crate::analyzer::AnalyzerQueryContext::default());
        analyzer.begin_query(&context);

        assert!(analyzer.global_usage_definition_index.get().is_none());
        assert!(analyzer.usage_facts_index.get().is_none());
        let definitions = analyzer.global_usage_definition_index_shared();
        let facts = analyzer.usage_facts_index_shared();

        assert!(definitions.fqn("Model").is_empty());
        assert!(facts.facts("Model").is_empty());
        let error = context
            .store_error()
            .expect("stale lazy index build should report its store error");
        assert!(error.to_string().contains("stale analyzer generation"));
        assert!(
            analyzer.global_usage_definition_index.get().is_none(),
            "stale read must not permanently cache an incomplete definition index"
        );
        assert!(
            analyzer.usage_facts_index.get().is_none(),
            "stale read must not permanently cache incomplete usage facts"
        );
        analyzer.end_query(&context);
    }

    #[test]
    fn stale_definition_query_records_failure_while_healthy_miss_does_not() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        std::fs::write(root.join("Model.java"), "class Model {}\n").unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Java));
        let analyzer = TreeSitterAnalyzer::new(project, JavaAdapter);

        let healthy = Arc::new(crate::analyzer::AnalyzerQueryContext::default());
        analyzer.begin_query(&healthy);
        assert!(analyzer.definitions("Missing").next().is_none());
        assert!(healthy.store_error().is_none());
        analyzer.end_query(&healthy);

        analyzer
            .store_context
            .store
            .ensure_language_epoch_value("java", "cutover-before-definition-read")
            .unwrap();
        let stale = Arc::new(crate::analyzer::AnalyzerQueryContext::default());
        analyzer.begin_query(&stale);
        assert!(analyzer.definitions("Model").next().is_none());
        let error = stale
            .store_error()
            .expect("stale definition query should report its store error");
        assert!(error.to_string().contains("querying definition candidates"));
        assert!(error.to_string().contains("stale analyzer generation"));
        analyzer.end_query(&stale);
    }

    #[test]
    fn shared_usage_indices_reuse_generation_allocations_and_reset_on_update() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/demo/Service.java");
        file.write("package demo; class Service { String before() { return \"before\"; } }\n")
            .expect("java source");

        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Java));
        let analyzer = TreeSitterAnalyzer::new(project, JavaAdapter);
        analyzer.reset_global_usage_definition_index_build_count_for_test();

        let first_definitions = analyzer.global_usage_definition_index_shared();
        let first_facts = analyzer.usage_facts_index_shared();
        let second_definitions = analyzer.global_usage_definition_index_shared();
        let second_facts = analyzer.usage_facts_index_shared();
        let cloned = analyzer.clone();
        let cloned_definitions = cloned.global_usage_definition_index_shared();
        let cloned_facts = cloned.usage_facts_index_shared();

        assert!(Arc::ptr_eq(&first_definitions, &second_definitions));
        assert!(Arc::ptr_eq(&first_facts, &second_facts));
        assert!(Arc::ptr_eq(&first_definitions, &cloned_definitions));
        assert!(Arc::ptr_eq(&first_facts, &cloned_facts));
        assert_eq!(
            analyzer.global_usage_definition_index_build_count_for_test(),
            1
        );
        assert_eq!(first_definitions.fqn("demo.Service.before").len(), 1);
        assert!(!first_facts.facts("demo.Service.before").is_empty());

        file.write("package demo; class Service { String after() { return \"after\"; } }\n")
            .expect("updated java source");
        let updated = analyzer.update(&BTreeSet::from([file]));
        let updated_definitions = updated.global_usage_definition_index_shared();
        let updated_facts = updated.usage_facts_index_shared();

        assert!(!Arc::ptr_eq(&first_definitions, &updated_definitions));
        assert!(!Arc::ptr_eq(&first_facts, &updated_facts));
        assert_eq!(
            updated.global_usage_definition_index_build_count_for_test(),
            1
        );
        assert_eq!(first_definitions.fqn("demo.Service.before").len(), 1);
        assert!(first_definitions.fqn("demo.Service.after").is_empty());
        assert!(!first_facts.facts("demo.Service.before").is_empty());
        assert!(first_facts.facts("demo.Service.after").is_empty());
        assert!(updated_definitions.fqn("demo.Service.before").is_empty());
        assert_eq!(updated_definitions.fqn("demo.Service.after").len(), 1);
        assert!(updated_facts.facts("demo.Service.before").is_empty());
        assert!(!updated_facts.facts("demo.Service.after").is_empty());
    }

    #[test]
    fn concurrent_clones_build_shared_usage_indices_once() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/demo/Service.java");
        file.write("package demo; class Service { String call() { return \"ok\"; } }\n")
            .expect("java source");

        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Java));
        let analyzer = TreeSitterAnalyzer::new(project, JavaAdapter);
        analyzer.reset_global_usage_definition_index_build_count_for_test();
        analyzer.reset_full_declaration_scan_count_for_test();
        let barrier = Arc::new(Barrier::new(32));

        let handles = std::thread::scope(|scope| {
            (0..32)
                .map(|_| {
                    let clone = analyzer.clone();
                    let barrier = Arc::clone(&barrier);
                    scope.spawn(move || {
                        barrier.wait();
                        (
                            clone.global_usage_definition_index_shared(),
                            clone.usage_facts_index_shared(),
                        )
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|handle| handle.join().expect("index worker"))
                .collect::<Vec<_>>()
        });

        for (definitions, facts) in &handles[1..] {
            assert!(Arc::ptr_eq(&handles[0].0, definitions));
            assert!(Arc::ptr_eq(&handles[0].1, facts));
        }
        assert_eq!(
            analyzer.global_usage_definition_index_build_count_for_test(),
            1
        );
        assert_eq!(analyzer.full_declaration_scan_count_for_test(), 1);
    }

    #[test]
    fn query_read_cache_keeps_broad_traversals_out_of_the_lru_eviction_loop() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        let files: Vec<_> = (0..=TRANSIENT_FILE_STATE_CACHE_CAPACITY)
            .map(|index| {
                let file = temp_file(&root, &format!("src/Type{index}.java"));
                file.write(format!("package demo; class Type{index} {{}}\n"))
                    .expect("java source");
                file
            })
            .collect();

        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Java));
        let analyzer = TreeSitterAnalyzer::new(project, JavaAdapter);
        analyzer.reset_full_hydration_count_for_test();

        let outer = Arc::new(crate::analyzer::AnalyzerQueryContext::default());
        let inner = Arc::new(crate::analyzer::AnalyzerQueryContext::default());
        analyzer.begin_query(&outer);
        for file in &files {
            assert!(analyzer.fetch_file_state(file).is_some());
        }
        analyzer.begin_query(&inner);
        for file in &files {
            assert!(analyzer.fetch_file_state(file).is_some());
        }
        analyzer.end_query(&inner);

        assert_eq!(
            analyzer.full_hydration_count_for_test(),
            TRANSIENT_FILE_STATE_CACHE_CAPACITY + 1
        );

        analyzer.end_query(&outer);
        assert!(analyzer.fetch_file_state(&files[0]).is_some());
        assert_eq!(
            analyzer.full_hydration_count_for_test(),
            TRANSIENT_FILE_STATE_CACHE_CAPACITY + 2
        );
    }

    #[test]
    fn query_read_cache_does_not_retain_prepared_syntax_past_capacity() {
        let context = Arc::new(crate::analyzer::AnalyzerQueryContext::default());
        let mut cache = QueryReadCache::default();
        cache.begin(&context);
        let first = PreparedSyntaxCacheKey {
            file_state: FileStateCacheKey {
                oid: Oid::hash_object(ObjectType::Blob, b"first").expect("first oid"),
                rel_path: PathBuf::from("first.cpp"),
            },
            origin: PreparedSourceOrigin::Disk,
            overlay_revision: None,
        };
        let second = PreparedSyntaxCacheKey {
            file_state: FileStateCacheKey {
                oid: Oid::hash_object(ObjectType::Blob, b"second").expect("second oid"),
                rel_path: PathBuf::from("second.cpp"),
            },
            origin: PreparedSourceOrigin::Disk,
            overlay_revision: None,
        };

        let first_cell = cache
            .prepared_syntax_cell_with_capacity(first.clone(), 1)
            .expect("first retained cell");
        let repeated = cache
            .prepared_syntax_cell_with_capacity(first, 1)
            .expect("existing retained cell");
        assert!(Arc::ptr_eq(&first_cell, &repeated));
        assert!(
            cache
                .prepared_syntax_cell_with_capacity(second, 1)
                .is_none(),
            "a new file must be prepared without retention at capacity"
        );
        assert_eq!(cache.prepared_syntax.len(), 1);
    }

    #[test]
    fn query_read_cache_reuses_analyzed_live_files_until_the_outer_scope_ends() {
        let context = Arc::new(crate::analyzer::AnalyzerQueryContext::default());
        let mut cache = QueryReadCache::default();
        let files = vec![ProjectFile::new(std::env::temp_dir(), "src/lib.rs")];

        cache.begin(&context);
        assert!(cache.analyzed_live_files().is_none());
        cache.retain_analyzed_live_files(files.clone());
        assert_eq!(cache.analyzed_live_files(), Some(files));

        cache.end(&context);
        assert!(
            cache.analyzed_live_files().is_none(),
            "a later analyzer request must validate its own live-file snapshot"
        );
    }

    #[test]
    fn prepared_syntax_is_reused_sequentially_within_outer_query_scope() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/main.rs");
        file.write("fn target() {}\nfn consumer() { target(); }\n")
            .expect("rust source");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Rust));
        let analyzer = TreeSitterAnalyzer::new(project, RustAdapter);
        let _scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);

        let first = analyzer.prepared_syntax(&file).expect("first syntax");
        let second = analyzer.prepared_syntax(&file).expect("reused syntax");

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(analyzer.prepared_syntax_parse_count_for_test(&file), 1);
        assert_eq!(
            first.source(),
            "fn target() {}\nfn consumer() { target(); }\n"
        );
    }

    #[test]
    fn prepared_syntax_initializes_once_for_concurrent_queries() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/main.rs");
        file.write("fn target() {}\nfn consumer() { target(); }\n")
            .expect("rust source");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Rust));
        let analyzer = TreeSitterAnalyzer::new(project, RustAdapter);
        let _scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
        let barrier = Arc::new(Barrier::new(8));

        let prepared: Vec<_> = std::thread::scope(|threads| {
            let analyzer = &analyzer;
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    let barrier = Arc::clone(&barrier);
                    let file = file.clone();
                    threads.spawn(move || {
                        barrier.wait();
                        analyzer.prepared_syntax(&file).expect("prepared syntax")
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("syntax worker"))
                .collect()
        });

        assert!(
            prepared
                .iter()
                .skip(1)
                .all(|syntax| Arc::ptr_eq(&prepared[0], syntax))
        );
        assert_eq!(analyzer.prepared_syntax_parse_count_for_test(&file), 1);
    }

    #[test]
    fn prepared_syntax_refreshes_after_outer_scope_and_overlay_change() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/main.rs");
        std::fs::create_dir_all(file.abs_path().parent().expect("source parent"))
            .expect("source directory");
        file.write("fn disk() {}\n").expect("rust source");
        let project = Arc::new(CountingOverlayProject::new(&root, "fn first() {}\n"));
        let analyzer =
            TreeSitterAnalyzer::new(Arc::clone(&project) as Arc<dyn Project>, RustAdapter);

        let first = {
            let _scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
            let prepared = analyzer.prepared_syntax(&file).expect("first syntax");
            assert_eq!(prepared.source(), "fn first() {}\n");
            assert_eq!(analyzer.prepared_syntax_parse_count_for_test(&file), 1);
            prepared
        };

        project.set_source("fn second() { first(); }\n");
        let _scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
        let second = analyzer.prepared_syntax(&file).expect("updated syntax");

        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(second.source(), "fn second() { first(); }\n");
        assert_eq!(analyzer.prepared_syntax_parse_count_for_test(&file), 1);
        assert_ne!(
            first.tree().root_node().to_sexp(),
            second.tree().root_node().to_sexp()
        );
    }

    #[test]
    fn prepared_syntax_limited_rejects_oversized_source_before_parsing() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/main.rs");
        let source = "fn target() {}\nfn consumer() { target(); }\n";
        file.write(source).expect("rust source");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Rust));
        let analyzer = TreeSitterAnalyzer::new(project, RustAdapter);
        let _scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);

        let exceeded = analyzer
            .prepared_syntax_limited(&file, source.len() - 1)
            .expect_err("source larger than the caller cap must not be parsed");
        assert_eq!(exceeded.minimum_source_bytes(), source.len());
        assert_eq!(analyzer.prepared_syntax_parse_count_for_test(&file), 0);

        let prepared = analyzer
            .prepared_syntax_limited(&file, source.len())
            .expect("exact source-size cap should be accepted")
            .expect("bounded source should prepare");
        assert_eq!(prepared.source(), source);
        assert_eq!(analyzer.prepared_syntax_parse_count_for_test(&file), 1);
    }

    #[test]
    fn prepared_syntax_accepts_an_empty_source_file() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/empty.rs");
        file.write("").expect("empty rust source");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Rust));
        let analyzer = TreeSitterAnalyzer::new(project, RustAdapter);

        let prepared = analyzer
            .prepared_syntax_limited(&file, 0)
            .expect("empty source fits a zero-byte preparation cap")
            .expect("empty source remains valid syntax input");

        assert_eq!(prepared.source(), "");
        assert_eq!(prepared.origin(), PreparedSourceOrigin::Disk);
        assert_eq!(prepared.overlay_revision(), None);
    }

    #[test]
    fn prepared_syntax_cache_identity_distinguishes_repeated_overlay_content() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/main.rs");
        file.write("fn disk() {}\n").expect("rust source");
        let base: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Rust));
        let overlay = Arc::new(OverlayProject::new(base));
        let analyzer =
            TreeSitterAnalyzer::new(Arc::clone(&overlay) as Arc<dyn Project>, RustAdapter);
        let repeated_source = "fn repeated() {}\n";

        assert!(overlay.set(file.abs_path(), repeated_source.to_owned()));
        let first = {
            let _scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
            analyzer.prepared_syntax(&file).expect("first overlay")
        };
        assert!(overlay.set(file.abs_path(), "fn middle() {}\n".to_owned()));
        let middle = {
            let _scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
            analyzer.prepared_syntax(&file).expect("middle overlay")
        };
        assert!(overlay.set(file.abs_path(), repeated_source.to_owned()));
        let repeated = {
            let _scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
            analyzer.prepared_syntax(&file).expect("repeated overlay")
        };

        assert_eq!(first.source(), repeated.source());
        assert_eq!(first.origin(), PreparedSourceOrigin::Overlay);
        assert_eq!(middle.origin(), PreparedSourceOrigin::Overlay);
        assert_eq!(repeated.origin(), PreparedSourceOrigin::Overlay);
        let first_revision = first.overlay_revision().expect("first overlay revision");
        let middle_revision = middle.overlay_revision().expect("middle overlay revision");
        let repeated_revision = repeated
            .overlay_revision()
            .expect("repeated overlay revision");
        assert!(first_revision < middle_revision);
        assert!(middle_revision < repeated_revision);
        assert_ne!(first_revision, repeated_revision);
        assert!(!Arc::ptr_eq(&first, &repeated));
    }

    #[test]
    fn query_read_cache_hashes_overlay_once_and_refreshes_after_outer_scope() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/main.rs");
        std::fs::create_dir_all(file.abs_path().parent().expect("source parent"))
            .expect("source directory");
        let source = "pub struct Example;\nimpl Example { pub fn value(&self) -> usize { 1 } }\n";
        file.write(source).expect("rust source");
        let project = Arc::new(CountingOverlayProject::new(root, source));
        let analyzer =
            TreeSitterAnalyzer::new(Arc::clone(&project) as Arc<dyn Project>, RustAdapter);
        project.reset_reads();

        let outer_scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
        let first_oid = analyzer
            .resolve_live_oid_for_file(&file)
            .expect("first overlay oid");
        assert_eq!(
            project.read_count(),
            1,
            "the first OID lookup reads the overlay"
        );
        assert_eq!(analyzer.resolve_live_oid_for_file(&file), Some(first_oid));
        assert_eq!(
            project.read_count(),
            1,
            "repeated OID lookup must use the query cache"
        );

        let declarations = analyzer.declarations(&file);
        let reads_after_hydration = project.read_count();
        for declaration in declarations {
            assert!(!analyzer.ranges(&declaration).is_empty());
        }
        assert_eq!(
            project.read_count(),
            reads_after_hydration,
            "range traversal must not reread the overlay"
        );

        {
            let _inner_scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
            assert_eq!(analyzer.resolve_live_oid_for_file(&file), Some(first_oid));
            assert_eq!(
                project.read_count(),
                reads_after_hydration,
                "nested scopes must reuse the outer cache"
            );
        }
        assert_eq!(analyzer.resolve_live_oid_for_file(&file), Some(first_oid));
        assert_eq!(
            project.read_count(),
            reads_after_hydration,
            "dropping the inner scope must retain the cache"
        );
        drop(outer_scope);

        project.set_source(format!("{source}\n"));
        let _next_scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
        let next_oid = analyzer
            .resolve_live_oid_for_file(&file)
            .expect("updated overlay oid");
        assert_ne!(
            next_oid, first_oid,
            "the next query must observe changed overlay text"
        );
        assert_eq!(
            project.read_count(),
            reads_after_hydration + 1,
            "the next query should read the overlay once"
        );
    }

    #[test]
    fn warm_rebuild_uses_bulk_presence_without_redundant_point_contains_queries() {
        const UNIQUE_FILES: usize = 10;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        for index in 0..UNIQUE_FILES {
            let file = ProjectFile::new(root.clone(), format!("pkg{index}/type{index}.py"));
            file.write(format!("class Type{index}:\n    pass\n"))
                .unwrap();
        }
        let shared_source = "class Shared:\n    pass\n";
        for path in ["dup_a/shared.py", "dup_b/shared.py"] {
            ProjectFile::new(root.clone(), path)
                .write(shared_source)
                .unwrap();
        }
        for path in ["broken_a/binary.py", "broken_b/binary.py"] {
            ProjectFile::new(root.clone(), path)
                .write("\0not parseable source")
                .unwrap();
        }
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.clone(), Language::Python));
        let store = Arc::new(
            AnalyzerStore::open_persistent(&temp.path().join("analyzer.db"))
                .expect("persistent analyzer store"),
        );
        let store_context = AnalyzerStoreContext {
            store: Arc::clone(&store),
            gc: Arc::new(crate::analyzer::store::gc::AnalyzerGcCoordinator::default()),
            liveness: None,
            live_paths: Arc::new(LivePathMap::default()),
            generations: Arc::new(HashMap::default()),
        };
        let config = AnalyzerConfig::default();

        let _cold = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            Arc::clone(&project),
            PythonAdapter,
            config.clone(),
            store_context.clone(),
            None,
        )
        .expect("analyzer epochs should initialize");
        store.reset_parsed_blob_point_contains_queries_for_test();
        let warm_parse_count = Arc::new(AtomicUsize::new(0));
        let warm_progress_count = Arc::clone(&warm_parse_count);
        let warm = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            Arc::clone(&project),
            PythonAdapter,
            config.clone(),
            store_context.clone(),
            Some(Arc::new(move |event| {
                if event.phase == BuildProgressPhase::Parse {
                    warm_progress_count.fetch_add(1, Ordering::Relaxed);
                }
            })),
        )
        .expect("analyzer epochs should initialize");
        let warm_point_queries = store.parsed_blob_point_contains_queries_for_test();
        assert_eq!(warm.get_definitions("dup_a.shared.Shared").len(), 1);
        assert_eq!(warm.get_definitions("dup_b.shared.Shared").len(), 1);

        let shared_oid = Oid::hash_object(ObjectType::Blob, shared_source.as_bytes()).unwrap();
        store.mark_parsed_blob_incomplete_for_test(shared_oid, "python");
        store.reset_parsed_blob_point_contains_queries_for_test();
        let parse_count = Arc::new(AtomicUsize::new(0));
        let progress_count = Arc::clone(&parse_count);
        let recovered = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            project,
            PythonAdapter,
            config,
            store_context,
            Some(Arc::new(move |event| {
                if event.phase == BuildProgressPhase::Parse {
                    progress_count.fetch_add(1, Ordering::Relaxed);
                }
            })),
        )
        .expect("analyzer epochs should initialize");
        let recovery_point_queries = store.parsed_blob_point_contains_queries_for_test();

        assert_eq!(
            warm_parse_count.load(Ordering::Relaxed),
            1,
            "one unparseable representative should cover both duplicate paths"
        );
        assert_eq!(
            parse_count.load(Ordering::Relaxed),
            2,
            "rebuild should parse one corrupt representative and retry the unparseable key once"
        );
        assert_eq!(recovered.get_definitions("dup_a.shared.Shared").len(), 1);
        assert_eq!(recovered.get_definitions("dup_b.shared.Shared").len(), 1);
        assert_eq!(
            (warm_point_queries, recovery_point_queries),
            (0, 0),
            "the authoritative bulk missing set should avoid per-file contains checks on warm and one-corrupt-key rebuilds"
        );
    }

    #[test]
    fn clone_with_project_has_an_independent_query_read_cache() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/main.rs");
        std::fs::create_dir_all(file.abs_path().parent().expect("source parent"))
            .expect("source directory");
        file.write("fn disk() {}\n").expect("rust source");

        let live_project = Arc::new(CountingOverlayProject::new(&root, "fn live() {}\n"));
        let analyzer =
            TreeSitterAnalyzer::new(Arc::clone(&live_project) as Arc<dyn Project>, RustAdapter);
        live_project.reset_reads();
        let _live_scope = crate::analyzer::AnalyzerQueryScope::new(&analyzer);
        let live_oid = analyzer
            .resolve_live_oid_for_file(&file)
            .expect("live overlay oid");

        let snapshot_project = Arc::new(CountingOverlayProject::new(
            &root,
            "fn frozen_snapshot() {}\n",
        ));
        let snapshot =
            analyzer.clone_with_project(Arc::clone(&snapshot_project) as Arc<dyn Project>);
        snapshot_project.reset_reads();
        let _snapshot_scope = crate::analyzer::AnalyzerQueryScope::new(&snapshot);
        let snapshot_oid = snapshot
            .resolve_live_oid_for_file(&file)
            .expect("snapshot overlay oid");

        assert_ne!(
            snapshot_oid, live_oid,
            "project snapshots must not share live OIDs"
        );
        assert_eq!(
            snapshot_project.read_count(),
            1,
            "snapshot should read its own overlay"
        );
    }

    #[test]
    fn file_summary_uses_persisted_projection_without_full_hydration() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), "src/demo/Example.java");
        file.write(
            "package demo; public class Example { public String name; public void run() {} }\n",
        )
        .expect("java source");

        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Java));
        let analyzer = JavaAnalyzer::new(project);
        analyzer.inner().reset_full_hydration_count_for_test();

        let first_projection = analyzer
            .summary_file_projection(&file)
            .expect("persisted summary projection");
        let second_projection = analyzer
            .summary_file_projection(&file)
            .expect("cached summary projection");
        assert!(Arc::ptr_eq(&first_projection, &second_projection));

        let result = crate::searchtools::summarize_files(&analyzer, vec![file]);

        assert_eq!(result.summaries.len(), 1);
        assert!(
            result.summaries[0]
                .elements
                .iter()
                .any(|element| element.symbol.contains("Example.run")),
            "persisted projection should render method summaries"
        );
        assert_eq!(analyzer.inner().full_hydration_count_for_test(), 0);
    }

    #[test]
    fn literal_symbol_search_keeps_members_of_matching_java_types() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), "src/demo/Gson.java");
        file.write(
            "package demo; public class Gson { public void fromJson() {} } class Other { void unrelated() {} }\n",
        )
        .expect("java source");

        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Java));
        let analyzer = TreeSitterAnalyzer::new(project, JavaAdapter);

        let matches = analyzer.search_definitions("Gson", false);
        let candidates = analyzer.search_symbol_candidates("Gson", false);

        assert!(matches.iter().any(|unit| unit.fq_name() == "demo.Gson"));
        assert!(
            matches
                .iter()
                .any(|unit| unit.fq_name() == "demo.Gson.fromJson")
        );
        assert!(!matches.iter().any(|unit| unit.short_name() == "unrelated"));
        assert!(candidates.iter().any(|candidate| {
            candidate.code_unit.fq_name() == "demo.Gson.fromJson"
                && candidate.primary_range.is_some()
                && !candidate.contains_tests
        }));
    }
}
