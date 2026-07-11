use crate::analyzer::cognitive_complexity;
use crate::analyzer::store::AnalyzerStore;
use crate::analyzer::store::liveness::{LivePathEntry, LivePathMap, LiveSnapshot, Liveness};
use crate::analyzer::store::query::QueryResolver;
use crate::analyzer::{
    AnalyzerConfig, CodeBaseMetrics, CodeUnit, CodeUnitType, DeclarationInfo,
    DefinitionLookupIndex, IAnalyzer, ImportInfo, Language, Project, ProjectFile, Range,
    RubyMethodDispatchMode, SearchSymbolCandidate, SignatureMetadata, SummaryFileProjection,
    UsageFactsIndex,
};
use crate::gitblob;
use crate::hash::{HashMap, HashSet, map_with_capacity, set_with_capacity};
use crate::profiling;
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
use git2::{ObjectType, Oid};
use rayon::prelude::*;
use regex::RegexBuilder;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::marker::PhantomData;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tree_sitter::{Language as TsLanguage, Node, Parser, Tree};

const TRANSIENT_FILE_STATE_CACHE_CAPACITY: usize = 128;
// A broad usage traversal may visit more files than the small cross-request
// cache holds. Retain hydrated states for one request, then release them.
const QUERY_FILE_STATE_CACHE_CAPACITY: usize = 1_024;
const SUMMARY_FILE_PROJECTION_CACHE_CAPACITY: usize = 32;
const STORE_WRITE_IMMEDIATE_RETRIES: usize = 2;
const STORE_WRITE_RETRY_BASE_DELAY: Duration = Duration::from_millis(250);
const STORE_WRITE_RETRY_MAX_DELAY: Duration = Duration::from_secs(30);

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
}

pub(crate) fn default_store_context(project: &dyn Project) -> AnalyzerStoreContext {
    store_context(project, false)
}

pub(crate) fn persistent_store_context(project: &dyn Project) -> AnalyzerStoreContext {
    store_context(project, true)
}

fn store_context(project: &dyn Project, persisted: bool) -> AnalyzerStoreContext {
    let store = if persisted {
        match project.persistence_root() {
            Some(root) => AnalyzerStore::open_for_workspace(root)
                .or_else(|_| AnalyzerStore::open_in_memory())
                .expect("failed to open analyzer store"),
            None => {
                AnalyzerStore::open_in_memory().expect("failed to open in-memory analyzer store")
            }
        }
    } else {
        AnalyzerStore::open_in_memory().expect("failed to open in-memory analyzer store")
    };
    let liveness = gitblob::discover(project.root())
        .and_then(|repo| Liveness::new(repo).ok())
        .map(Arc::new);
    AnalyzerStoreContext {
        store: Arc::new(store),
        gc: Arc::new(crate::analyzer::store::gc::AnalyzerGcCoordinator::default()),
        liveness,
        live_paths: Arc::new(LivePathMap::default()),
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
    fn parser_language(&self) -> TsLanguage;
    fn parser_language_for_file(&self, _file: &ProjectFile) -> TsLanguage {
        self.parser_language()
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
    fn storage_content_qualifier(&self, code_unit: &CodeUnit) -> String {
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
        None
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
    pub(crate) top_level_declarations: Vec<CodeUnit>,
    pub(crate) declarations: HashSet<CodeUnit>,
    pub(crate) definition_lookup_units: HashSet<CodeUnit>,
    pub(crate) import_statements: Vec<String>,
    pub(crate) imports: Vec<ImportInfo>,
    pub(crate) raw_supertypes: HashMap<CodeUnit, Vec<String>>,
    pub(crate) type_identifiers: HashSet<String>,
    pub(crate) signatures: HashMap<CodeUnit, Vec<String>>,
    pub(crate) signature_metadata: HashMap<CodeUnit, Vec<SignatureMetadata>>,
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

#[derive(Debug, Clone)]
struct DirtyFileState {
    state: FileState,
    attempts: usize,
    next_retry_at: Instant,
    _last_error: String,
}

#[derive(Debug, Default)]
struct AnalyzerRuntimeState {
    fresh_parse_errors: HashMap<ProjectFile, Vec<crate::analyzer::ParseError>>,
    dirty_file_states: Mutex<HashMap<FileStateCacheKey, DirtyFileState>>,
    seeded_file_states: Vec<(FileStateCacheKey, Arc<FileState>)>,
}

impl AnalyzerRuntimeState {
    fn new(
        fresh_parse_errors: HashMap<ProjectFile, Vec<crate::analyzer::ParseError>>,
        dirty_file_states: HashMap<FileStateCacheKey, DirtyFileState>,
        seeded_file_states: Vec<(FileStateCacheKey, Arc<FileState>)>,
    ) -> Self {
        Self {
            fresh_parse_errors,
            dirty_file_states: Mutex::new(dirty_file_states),
            seeded_file_states,
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
}

struct ReconcileFileStates {
    files: Vec<ProjectFile>,
    replace_live_paths: bool,
    progress: Option<BuildProgress>,
    dirty_file_states: HashMap<FileStateCacheKey, DirtyFileState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FileStateCacheKey {
    oid: Oid,
    rel_path: std::path::PathBuf,
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
    depth: usize,
    live_oids: HashMap<ProjectFile, Option<Oid>>,
    file_states: HashMap<FileStateCacheKey, Arc<FileState>>,
}

impl QueryReadCache {
    fn begin(&mut self) {
        if self.depth == 0 {
            self.live_oids.clear();
            self.file_states.clear();
        }
        self.depth += 1;
    }

    fn end(&mut self) {
        self.depth = self.depth.saturating_sub(1);
        if self.depth == 0 {
            self.live_oids.clear();
            self.file_states.clear();
        }
    }

    fn is_active(&self) -> bool {
        self.depth > 0
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
    pub top_level_declarations: Vec<CodeUnit>,
    pub declarations: HashSet<CodeUnit>,
    pub definition_lookup_units: HashSet<CodeUnit>,
    pub import_statements: Vec<String>,
    pub imports: Vec<ImportInfo>,
    pub raw_supertypes: HashMap<CodeUnit, Vec<String>>,
    pub type_identifiers: HashSet<String>,
    pub signatures: HashMap<CodeUnit, Vec<String>>,
    pub signature_metadata: HashMap<CodeUnit, Vec<SignatureMetadata>>,
    pub ruby_method_dispatch_modes: HashMap<CodeUnit, RubyMethodDispatchMode>,
    pub scala_traits: HashSet<CodeUnit>,
    pub type_aliases: HashSet<CodeUnit>,
    pub(crate) ranges: HashMap<CodeUnit, Vec<Range>>,
    pub(crate) children: HashMap<CodeUnit, Vec<CodeUnit>>,
}

impl ParsedFile {
    pub fn new(package_name: String) -> Self {
        Self {
            package_name,
            top_level_declarations: Vec::new(),
            declarations: HashSet::default(),
            definition_lookup_units: HashSet::default(),
            import_statements: Vec::new(),
            imports: Vec::new(),
            raw_supertypes: HashMap::default(),
            type_identifiers: HashSet::default(),
            signatures: HashMap::default(),
            signature_metadata: HashMap::default(),
            ruby_method_dispatch_modes: HashMap::default(),
            scala_traits: HashSet::default(),
            type_aliases: HashSet::default(),
            ranges: HashMap::default(),
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
        let inserted = self.declarations.insert(code_unit.clone());

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
        let inserted = self.declarations.insert(code_unit.clone());

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
        if self.declarations.contains(&code_unit) {
            return;
        }

        self.top_level_declarations.push(code_unit.clone());
        self.declarations.insert(code_unit.clone());
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

    pub fn set_raw_supertypes(&mut self, code_unit: CodeUnit, raw_supertypes: Vec<String>) {
        self.raw_supertypes.insert(code_unit, raw_supertypes);
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
        self.declarations.remove(code_unit);
        self.definition_lookup_units.remove(code_unit);
        self.raw_supertypes.remove(code_unit);
        self.signatures.remove(code_unit);
        self.signature_metadata.remove(code_unit);
        self.ruby_method_dispatch_modes.remove(code_unit);
        self.scala_traits.remove(code_unit);
        self.type_aliases.remove(code_unit);
        self.ranges.remove(code_unit);
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
    store_context: AnalyzerStoreContext,
    /// Per-request persisted read model. Live OIDs are validated once and
    /// hydrated states remain available for the graph traversal.
    query_read_cache: Arc<Mutex<QueryReadCache>>,
    transient_file_states: Arc<Mutex<FileStateCache>>,
    source_snapshot_file_states: Arc<Mutex<FileStateCache>>,
    summary_file_projections: Arc<Mutex<SummaryFileProjectionCache>>,
    definition_lookup_index: Arc<OnceLock<DefinitionLookupIndex>>,
    usage_facts_index: Arc<OnceLock<UsageFactsIndex>>,
    full_hydration_count: Arc<AtomicUsize>,
    bulk_hydration_count: Arc<AtomicUsize>,
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
            store_context: self.store_context.clone(),
            query_read_cache: Arc::clone(&self.query_read_cache),
            transient_file_states: Arc::clone(&self.transient_file_states),
            source_snapshot_file_states: Arc::clone(&self.source_snapshot_file_states),
            summary_file_projections: Arc::clone(&self.summary_file_projections),
            definition_lookup_index: Arc::clone(&self.definition_lookup_index),
            usage_facts_index: Arc::clone(&self.usage_facts_index),
            full_hydration_count: Arc::clone(&self.full_hydration_count),
            bulk_hydration_count: Arc::clone(&self.bulk_hydration_count),
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
    }

    pub(crate) fn new_with_config_storage_context_and_progress(
        project: Arc<dyn Project>,
        adapter: A,
        config: AnalyzerConfig,
        store_context: AnalyzerStoreContext,
        progress: Option<BuildProgress>,
    ) -> Self {
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
    }

    fn new_internal(
        project: Arc<dyn Project>,
        adapter: A,
        config: AnalyzerConfig,
        progress: Option<BuildProgress>,
        store_context: Option<AnalyzerStoreContext>,
    ) -> Self {
        let adapter = Arc::new(adapter);
        let store_context =
            store_context.unwrap_or_else(|| default_store_context(project.as_ref()));
        for (storage_key, parser_language) in adapter.storage_language_keys() {
            let _ = store_context.store.ensure_language_epoch_value(
                &storage_key,
                crate::analyzer::store::epoch::epoch_for(adapter.language(), &parser_language),
            );
        }
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
        Self {
            project,
            adapter,
            config,
            state,
            structural_cache,
            store_context,
            query_read_cache: Arc::new(Mutex::new(QueryReadCache::default())),
            transient_file_states: Arc::new(Mutex::new(FileStateCache::new(
                TRANSIENT_FILE_STATE_CACHE_CAPACITY,
            ))),
            source_snapshot_file_states: Arc::new(Mutex::new(source_snapshot_file_states)),
            summary_file_projections: Arc::new(Mutex::new(SummaryFileProjectionCache::new(
                SUMMARY_FILE_PROJECTION_CACHE_CAPACITY,
            ))),
            definition_lookup_index: Arc::new(OnceLock::new()),
            usage_facts_index: Arc::new(OnceLock::new()),
            full_hydration_count: Arc::new(AtomicUsize::new(0)),
            bulk_hydration_count: Arc::new(AtomicUsize::new(0)),
            _state: PhantomData,
        }
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
            store_context,
            query_read_cache: Arc::new(Mutex::new(QueryReadCache::default())),
            transient_file_states: Arc::new(Mutex::new(FileStateCache::new(
                TRANSIENT_FILE_STATE_CACHE_CAPACITY,
            ))),
            source_snapshot_file_states: Arc::new(Mutex::new(source_snapshot_file_states)),
            summary_file_projections: Arc::new(Mutex::new(SummaryFileProjectionCache::new(
                SUMMARY_FILE_PROJECTION_CACHE_CAPACITY,
            ))),
            definition_lookup_index: Arc::new(OnceLock::new()),
            usage_facts_index: Arc::new(OnceLock::new()),
            full_hydration_count: Arc::new(AtomicUsize::new(0)),
            bulk_hydration_count: Arc::new(AtomicUsize::new(0)),
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
            package_name: parsed.package_name,
            top_level_declarations: parsed.top_level_declarations,
            declarations: parsed.declarations,
            definition_lookup_units: parsed.definition_lookup_units,
            import_statements: parsed.import_statements,
            imports: parsed.imports,
            raw_supertypes: parsed.raw_supertypes,
            type_identifiers: parsed.type_identifiers,
            signatures: parsed.signatures,
            signature_metadata: parsed.signature_metadata,
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

    fn resolve_live_oids(
        project: &dyn Project,
        files: &[ProjectFile],
        store_context: &AnalyzerStoreContext,
        replace_live_paths: bool,
    ) -> Result<HashMap<ProjectFile, Oid>, String> {
        let mut out = map_with_capacity(files.len());
        let mut live_entries = Vec::new();
        for file in files {
            if !file.exists() && !project.has_overlay(file) {
                continue;
            }
            let (oid, entry) = if project.has_overlay(file) {
                let source = project.read_source(file).map_err(|err| err.to_string())?;
                let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes())
                    .map_err(|err| err.to_string())?;
                (oid, LivePathEntry::overlay(file.clone(), oid))
            } else if let Some(liveness) = store_context.liveness.as_ref() {
                let Some(oid) = liveness.oid_for_path(file)? else {
                    continue;
                };
                (oid, LivePathEntry::filesystem(file.clone(), oid))
            } else {
                let bytes = std::fs::read(file.abs_path()).map_err(|err| err.to_string())?;
                let oid =
                    Oid::hash_object(ObjectType::Blob, &bytes).map_err(|err| err.to_string())?;
                (oid, LivePathEntry::overlay(file.clone(), oid))
            };
            live_entries.push(entry);
            out.insert(file.clone(), oid);
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
            },
        );

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
        } = input;
        let mut fresh_parse_errors = HashMap::default();
        let mut seeded_file_states = Vec::new();
        let oid_plan = Self::resolve_live_oids(project, &files, store_context, replace_live_paths);
        match oid_plan {
            Ok(file_oids) => {
                let all_blob_keys: Vec<_> = file_oids
                    .iter()
                    .map(|(file, oid)| (*oid, adapter.storage_language_key_for_file(file)))
                    .collect();
                let missing = store_context
                    .store
                    .missing_parsed_blob_keys(&all_blob_keys)
                    .unwrap_or(all_blob_keys);
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
                for (file, oid) in &file_oids {
                    let storage_key = adapter.storage_language_key_for_file(file);
                    if missing_blob_keys.contains(&(*oid, storage_key.clone())) {
                        representative_by_blob_key
                            .entry((*oid, storage_key))
                            .or_insert_with(|| file.clone());
                    }
                }
                let parse_targets: Vec<_> = missing
                    .iter()
                    .filter_map(|blob_key| representative_by_blob_key.get(blob_key).cloned())
                    .collect();
                let mut failed_blob_keys = HashSet::default();
                let mut parsed_files = HashSet::default();
                for (file, state) in
                    Self::analyze_files(adapter, project, config, parse_targets, progress.clone())
                {
                    let Some(oid) = file_oids.get(&file).copied() else {
                        continue;
                    };
                    let storage_key = adapter.storage_language_key_for_file(&file);
                    match state {
                        Some(state) => {
                            let key = Self::transient_cache_key(oid, &file);
                            Self::persist_or_mark_dirty(
                                &mut dirty_file_states,
                                store_context,
                                adapter,
                                &file,
                                oid,
                                &storage_key,
                                &state,
                            );
                            if let Some(errors) = state.parse_errors.clone() {
                                fresh_parse_errors.insert(file.clone(), errors);
                            }
                            if seeded_file_states.len() < TRANSIENT_FILE_STATE_CACHE_CAPACITY {
                                seeded_file_states.push((key, Arc::new(state)));
                            }
                            parsed_files.insert(file);
                        }
                        None => {
                            failed_blob_keys.insert((oid, storage_key));
                        }
                    }
                }

                let mut hydrate_misses = Vec::new();
                for file in &files {
                    if parsed_files.contains(file) {
                        continue;
                    }
                    let Some(oid) = file_oids.get(file).copied() else {
                        continue;
                    };
                    let storage_key = adapter.storage_language_key_for_file(file);
                    if failed_blob_keys.contains(&(oid, storage_key.clone())) {
                        continue;
                    }
                    if !store_context
                        .store
                        .contains_parsed_blob(oid, &storage_key)
                        .unwrap_or(false)
                    {
                        hydrate_misses.push(file.clone());
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
                        Self::persist_or_mark_dirty(
                            &mut dirty_file_states,
                            store_context,
                            adapter,
                            &file,
                            oid,
                            &storage_key,
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
                        Self::persist_or_mark_dirty(
                            &mut dirty_file_states,
                            store_context,
                            adapter,
                            &file,
                            oid,
                            &storage_key,
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

        AnalyzerRuntimeState::new(fresh_parse_errors, dirty_file_states, seeded_file_states)
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

    fn dirty_file_state(state: FileState, attempts: usize, last_error: String) -> DirtyFileState {
        DirtyFileState {
            state,
            attempts,
            next_retry_at: Instant::now() + Self::dirty_retry_delay(attempts),
            _last_error: last_error,
        }
    }

    fn write_parsed_blob_with_retries(
        store_context: &AnalyzerStoreContext,
        adapter: &A,
        oid: Oid,
        storage_key: &str,
        state: &FileState,
    ) -> std::result::Result<usize, String> {
        let mut last_error = String::new();
        for attempt in 1..=STORE_WRITE_IMMEDIATE_RETRIES + 1 {
            match store_context
                .store
                .write_parsed_blob(oid, storage_key, adapter, state)
            {
                Ok(()) => return Ok(attempt),
                Err(err) => {
                    last_error = err.to_string();
                    if attempt <= STORE_WRITE_IMMEDIATE_RETRIES {
                        std::thread::sleep(Duration::from_millis(10 * attempt as u64));
                    }
                }
            }
        }
        Err(last_error)
    }

    fn persist_or_mark_dirty(
        dirty_file_states: &mut HashMap<FileStateCacheKey, DirtyFileState>,
        store_context: &AnalyzerStoreContext,
        adapter: &A,
        file: &ProjectFile,
        oid: Oid,
        storage_key: &str,
        state: &FileState,
    ) {
        let key = Self::transient_cache_key(oid, file);
        match Self::write_parsed_blob_with_retries(store_context, adapter, oid, storage_key, state)
        {
            Ok(_) => {
                dirty_file_states.remove(&key);
            }
            Err(err) => {
                dirty_file_states.insert(
                    key,
                    Self::dirty_file_state(state.clone(), STORE_WRITE_IMMEDIATE_RETRIES + 1, err),
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
    ) -> Option<FileState> {
        let state = {
            let dirty_file_states = self
                .state
                .dirty_file_states
                .lock()
                .expect("dirty file-state mutex poisoned");
            let dirty = dirty_file_states.get(key)?;
            if Instant::now() < dirty.next_retry_at {
                return Some(dirty.state.clone());
            }
            dirty.state.clone()
        };

        match self.store_context.store.write_parsed_blob(
            key.oid,
            storage_key,
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
                    .insert(key.clone(), Arc::new(state.clone()));
                Some(state)
            }
            Err(err) => {
                let mut dirty_file_states = self
                    .state
                    .dirty_file_states
                    .lock()
                    .expect("dirty file-state mutex poisoned");
                if let Some(dirty) = dirty_file_states.get_mut(key) {
                    dirty.attempts = dirty.attempts.saturating_add(1);
                    dirty.next_retry_at = Instant::now() + Self::dirty_retry_delay(dirty.attempts);
                    dirty._last_error = err.to_string();
                    return Some(dirty.state.clone());
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
        let storage_key = self.adapter.storage_language_key_for_file(file);
        if let Some(state) = self.retry_dirty_file_state(&key, &storage_key) {
            return Some(Arc::new(state));
        }
        if let Some(state) = self
            .query_read_cache
            .lock()
            .expect("query read cache mutex poisoned")
            .file_state(&key)
        {
            return Some(state);
        }
        if let Some(state) = self
            .transient_file_states
            .lock()
            .expect("transient file-state cache mutex poisoned")
            .get(&key)
        {
            let mut query_cache = self
                .query_read_cache
                .lock()
                .expect("query read cache mutex poisoned");
            if query_cache.is_active() {
                query_cache.retain_file_state(key, Arc::clone(&state));
            }
            return Some(state);
        }

        self.full_hydration_count.fetch_add(1, Ordering::Relaxed);
        let source = self.source_for_oid(file, oid)?;
        let mut state = match self
            .store_context
            .store
            .hydrate_file_state_with_source(oid, &storage_key, self.adapter.as_ref(), file, &source)
            .ok()
            .flatten()
        {
            Some(state) => state,
            None => self.parse_and_store_transient(file, oid, source.clone())?,
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
            query_cache.retain_file_state(key, Arc::clone(&state));
        }
        Some(state)
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
                out.insert(file, state);
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
            .store_context
            .store
            .hydrate_file_states_by_key(&entries, self.adapter.as_ref(), &source_by_file)
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
                out.insert(file, state.imports);
            } else {
                clean_entries.push((file, oid, storage_key));
            }
        }
        let entries = clean_entries;
        if entries.is_empty() {
            return out;
        }
        let mut imports = self
            .store_context
            .store
            .hydrate_import_infos_by_key(&entries, self.adapter.as_ref())
            .unwrap_or_default();
        self.bulk_hydration_count
            .fetch_add(imports.len(), Ordering::Relaxed);
        for (file, oid, _) in entries {
            if imports.contains_key(&file) {
                continue;
            }
            if let Some(source) = self.source_for_oid(&file, oid)
                && let Some(state) = self.parse_and_store_transient(&file, oid, source)
            {
                imports.insert(file, state.imports);
            }
        }
        out.extend(imports);
        out
    }

    fn resolve_live_oid_for_file(&self, file: &ProjectFile) -> Option<Oid> {
        if self.project.has_overlay(file) {
            let source = self.project.read_source(file).ok()?;
            return Oid::hash_object(ObjectType::Blob, source.as_bytes()).ok();
        }
        {
            let cache = self
                .query_read_cache
                .lock()
                .expect("query read cache mutex poisoned");
            if cache.is_active()
                && let Some(oid) = cache.live_oids.get(file).copied()
            {
                return oid;
            }
        }
        let oid = if let Some(oid) = self
            .store_context
            .live_paths
            .snapshot()
            .validated_oid_for_path(file)
        {
            Some(oid)
        } else if let Some(liveness) = self.store_context.liveness.as_ref()
            && let Ok(Some(oid)) = liveness.oid_for_path(file)
        {
            Some(oid)
        } else if file.exists()
            && let Ok(bytes) = std::fs::read(file.abs_path())
            && let Ok(oid) = Oid::hash_object(ObjectType::Blob, &bytes)
        {
            Some(oid)
        } else {
            self.git_index_oid_for_file(file)
        };
        let mut cache = self
            .query_read_cache
            .lock()
            .expect("query read cache mutex poisoned");
        if cache.is_active() {
            cache.live_oids.insert(file.clone(), oid);
        }
        oid
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
        let mut parser = Self::build_parser(self.adapter.parser_language());
        let state = Self::analyze_source(&mut parser, self.adapter.as_ref(), file, source)?;
        let storage_key = self.adapter.storage_language_key_for_file(file);
        let key = Self::transient_cache_key(oid, file);
        match Self::write_parsed_blob_with_retries(
            &self.store_context,
            self.adapter.as_ref(),
            oid,
            &storage_key,
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
                self.state
                    .dirty_file_states
                    .lock()
                    .expect("dirty file-state mutex poisoned")
                    .insert(
                        key,
                        Self::dirty_file_state(
                            state.clone(),
                            STORE_WRITE_IMMEDIATE_RETRIES + 1,
                            err,
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
        let snapshot = self.live_snapshot();
        let mut files = Vec::new();
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
            if self
                .store_context
                .store
                .contains_parsed_blob(oid, &storage_key)
                .unwrap_or(false)
            {
                files.push(project_file);
            }
        }
        files.sort();
        files.dedup();
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

    fn rebase_live_file_to_project_root(&self, file: &ProjectFile) -> Option<ProjectFile> {
        crate::analyzer::common::rebase_project_file_to_root(file, self.project.root())
    }

    fn sql_nonpersisted_workspace_declarations_vec_matching(
        &self,
        mut keep: impl FnMut(&CodeUnit) -> bool,
    ) -> Option<Vec<CodeUnit>> {
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
                .blobs_with_structured_imports_by_keys(&blob_keys)
                .ok()?;
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
        Some(declarations)
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
                states.push(state);
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

    fn sql_definition_lookup_index(&self) -> Option<DefinitionLookupIndex> {
        let snapshot = self.live_snapshot();
        let mut blob_keys = Vec::new();
        for file in snapshot.all_paths() {
            let Some(project_file) = self.rebase_live_file_to_project_root(file) else {
                continue;
            };
            if crate::analyzer::common::language_for_file(&project_file) != self.adapter.language()
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

        let rows = self
            .store_context
            .store
            .definition_lookup_candidate_rows_by_keys(&blob_keys)
            .ok()?;
        let mut units = self.resolve_candidate_rows(rows);
        units.retain(|unit| !unit.is_file_scope());
        units.extend(self.dirty_units_matching(true, |_| true));
        units.extend(
            self.sql_nonpersisted_workspace_declarations_vec_matching(|unit| {
                !unit.is_file_scope()
            })?,
        );
        Some(DefinitionLookupIndex::from_declarations(
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
        self.store_context
            .store
            .write_parsed_blob(
                oid,
                &self.adapter.storage_language_key_for_file(file),
                self.adapter.as_ref(),
                &state,
            )
            .ok()?;
        if let Some(liveness) = self.store_context.liveness.as_ref() {
            liveness.refresh_overlay([live_entry.clone()]).ok()?;
        }
        self.store_context.live_paths.refresh([live_entry]);
        Some(())
    }

    fn sql_all_declarations_vec(&self) -> Option<Vec<CodeUnit>> {
        let rows = self
            .store_context
            .store
            .declaration_candidate_rows_for_langs(&self.storage_language_keys_for_queries())
            .ok()?;
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
        let rows = self
            .store_context
            .store
            .declaration_candidate_rows_with_primary_ranges_for_langs(
                &self.storage_language_keys_for_queries(),
            )
            .ok()?;
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

    fn definition_candidate_short_names(&self, normalized_fq_name: &str) -> Vec<String> {
        let mut names = self
            .adapter
            .lookup_candidate_short_names(normalized_fq_name);
        names.sort();
        names.dedup();
        names
    }

    fn definition_sort_key_for_unit(
        &self,
        code_unit: &CodeUnit,
    ) -> (i32, usize, String, String, String, String) {
        let first_start_byte = self
            .ranges(code_unit)
            .into_iter()
            .map(|range| range.start_byte)
            .min()
            .unwrap_or(usize::MAX);
        (
            self.adapter.definition_priority(code_unit),
            first_start_byte,
            code_unit.source().to_string().to_ascii_lowercase(),
            code_unit.fq_name().to_ascii_lowercase(),
            code_unit.signature().unwrap_or("").to_ascii_lowercase(),
            format!("{:?}", code_unit.kind()),
        )
    }

    fn sql_definitions_vec(&self, fq_name: &str) -> Option<Vec<CodeUnit>> {
        let normalized = self.adapter.normalize_full_name(fq_name);
        let langs = self.storage_language_keys_for_queries();
        let candidate_names = self.definition_candidate_short_names(&normalized);
        let rows = if candidate_names.is_empty() {
            self.store_context
                .store
                .declaration_candidate_rows_for_langs(&langs)
                .ok()?
        } else {
            let mut rows = Vec::new();
            for short_name in candidate_names {
                rows.extend(
                    self.store_context
                        .store
                        .declaration_candidate_rows_by_short_name_for_langs(&langs, &short_name)
                        .ok()?,
                );
            }
            rows
        };
        let mut matches: Vec<_> = self
            .resolve_candidate_rows(rows)
            .into_iter()
            .filter(|unit| self.adapter.normalize_full_name(&unit.fq_name()) == normalized)
            .collect();
        matches.extend(self.dirty_units_matching(false, |unit| {
            self.adapter.normalize_full_name(&unit.fq_name()) == normalized
        }));
        matches.extend(
            self.sql_nonpersisted_workspace_declarations_vec_matching(|unit| {
                self.adapter.normalize_full_name(&unit.fq_name()) == normalized
            })?,
        );
        matches.sort_by_cached_key(|code_unit| self.definition_sort_key_for_unit(code_unit));
        matches.dedup();

        let mut saw_module = false;
        matches.retain(|code_unit| {
            if !code_unit.is_module() {
                return true;
            }
            if saw_module {
                false
            } else {
                saw_module = true;
                true
            }
        });
        Some(matches)
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
            self.store_context
                .store
                .declaration_candidate_rows_by_literal_substring_for_langs(
                    &storage_languages,
                    &pattern,
                )
                .ok()?
        } else {
            self.store_context
                .store
                .declaration_candidate_rows_by_pattern_for_langs(&storage_languages, &pattern)
                .ok()?
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
            pattern.to_string()
        };
        let compiled = RegexBuilder::new(&pattern)
            .case_insensitive(true)
            .build()
            .ok()?;
        let rows = self
            .store_context
            .store
            .search_candidate_rows_by_pattern_for_langs(
                &self.storage_language_keys_for_queries(),
                &pattern,
            )
            .ok()?;
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

    pub(crate) fn ruby_method_dispatch_mode(
        &self,
        code_unit: &CodeUnit,
    ) -> Option<RubyMethodDispatchMode> {
        self.fetch_file_state(code_unit.source())
            .and_then(|state| state.ruby_method_dispatch_modes.get(code_unit).copied())
    }

    pub(crate) fn import_info_of(&self, file: &ProjectFile) -> Vec<ImportInfo> {
        self.fetch_file_state(file)
            .map(|state| state.imports.clone())
            .unwrap_or_default()
    }

    pub(crate) fn raw_supertypes_of(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.fetch_file_state(code_unit.source())
            .and_then(|state| state.raw_supertypes.get(code_unit).cloned())
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
            .store_context
            .store
            .declaration_candidate_rows_for_langs(&self.storage_language_keys_for_queries())
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
    pub(crate) fn definition_lookup_index_shared(&self) -> Arc<DefinitionLookupIndex> {
        Arc::new(self.definition_lookup_index().clone())
    }

    /// Owned handle to the derived callable-facts index; see
    /// [`Self::definition_lookup_index_shared`].
    pub(crate) fn usage_facts_index_shared(&self) -> Arc<UsageFactsIndex> {
        Arc::new(self.usage_facts_index().clone())
    }

    fn build_usage_facts_index(&self) -> UsageFactsIndex {
        let declarations = self.sql_all_declarations_vec().unwrap_or_default();
        let resolver = QueryResolver::from_snapshot(
            self.adapter.as_ref(),
            self.project.root(),
            self.live_snapshot(),
        );
        let mut facts_by_declaration = HashMap::default();
        let rows = self
            .store_context
            .store
            .usage_fact_rows_for_langs(&self.storage_language_keys_for_queries())
            .unwrap_or_default();
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
        UsageFactsIndex::build_from_declarations(
            self.definition_lookup_index(),
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
        )
    }
}

impl<A> crate::analyzer::IAnalyzer for TreeSitterAnalyzer<A>
where
    A: LanguageAdapter,
{
    fn begin_query(&self) {
        let mut cache = self
            .query_read_cache
            .lock()
            .expect("query read cache mutex poisoned");
        cache.begin();
    }

    fn end_query(&self) {
        let mut cache = self
            .query_read_cache
            .lock()
            .expect("query read cache mutex poisoned");
        cache.end();
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
            .store_context
            .store
            .summary_file_projection(oid, &storage_key, self.adapter.as_ref(), file)
            .ok()
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
                    .store_context
                    .store
                    .contains_parsed_blob(oid, &storage_key)
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
            },
        );
        store_context
            .gc
            .schedule(self.project.root(), Arc::clone(&store_context.store));
        Self::from_state(
            Arc::clone(&self.project),
            Arc::clone(&self.adapter),
            self.config.clone(),
            state,
            Arc::clone(&self.structural_cache),
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
        Box::new(
            self.sql_definitions_vec(fq_name)
                .unwrap_or_default()
                .into_iter(),
        )
    }

    fn definition_lookup_index(&self) -> &DefinitionLookupIndex {
        self.definition_lookup_index
            .get_or_init(|| self.sql_definition_lookup_index().unwrap_or_default())
    }

    fn usage_facts_index(&self) -> &UsageFactsIndex {
        self.usage_facts_index
            .get_or_init(|| self.build_usage_facts_index())
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
    use crate::analyzer::{AnalyzerConfig, IAnalyzer, JavaAnalyzer, Language, TestProject};
    use git2::{ObjectType, Oid};
    use std::path::Path;

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
            top_level_declarations: Vec::new(),
            declarations: HashSet::default(),
            definition_lookup_units: HashSet::default(),
            import_statements: Vec::new(),
            imports: Vec::new(),
            raw_supertypes: HashMap::default(),
            type_identifiers: HashSet::default(),
            signatures: HashMap::default(),
            signature_metadata: HashMap::default(),
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
                parsed,
                32,
                "forced test persistence failure".to_string(),
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
        };
        let config = AnalyzerConfig::default();
        let analyzer = TreeSitterAnalyzer::from_state(
            project,
            adapter,
            config.clone(),
            AnalyzerRuntimeState::new(HashMap::default(), dirty, Vec::new()),
            Arc::new(TreeSitterAnalyzer::<PythonAdapter>::build_structural_cache(
                &config,
            )),
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
                parsed,
                32,
                "forced test persistence failure".to_string(),
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
        };
        let config = AnalyzerConfig::default();
        let analyzer = TreeSitterAnalyzer::from_state(
            project,
            adapter,
            config.clone(),
            AnalyzerRuntimeState::new(HashMap::default(), dirty, Vec::new()),
            Arc::new(TreeSitterAnalyzer::<PythonAdapter>::build_structural_cache(
                &config,
            )),
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
        assert_eq!(adapter.storage_content_qualifier(&unit), "example");
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
        assert_eq!(python.storage_content_qualifier(&python_unit), "");
        assert_eq!(python.storage_file_content_qualifier("pkg.service"), "");
        assert_eq!(
            python.hydrate_content_qualifier("", &python_file),
            "pkg.service"
        );

        let rust_file = temp_file(&root, "src/net/mod.rs");
        let rust = RustAdapter;
        let rust_unit = CodeUnit::new(rust_file.clone(), CodeUnitType::Class, "net", "Client");
        assert_eq!(rust.storage_content_qualifier(&rust_unit), "");
        assert_eq!(rust.hydrate_content_qualifier("", &rust_file), "net");

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
        assert_eq!(go.storage_content_qualifier(&go_unit), "");
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

        analyzer.begin_query();
        for file in &files {
            assert!(analyzer.fetch_file_state(file).is_some());
        }
        analyzer.begin_query();
        for file in &files {
            assert!(analyzer.fetch_file_state(file).is_some());
        }
        analyzer.end_query();

        assert_eq!(
            analyzer.full_hydration_count_for_test(),
            TRANSIENT_FILE_STATE_CACHE_CAPACITY + 1
        );

        analyzer.end_query();
        assert!(analyzer.fetch_file_state(&files[0]).is_some());
        assert_eq!(
            analyzer.full_hydration_count_for_test(),
            TRANSIENT_FILE_STATE_CACHE_CAPACITY + 2
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
