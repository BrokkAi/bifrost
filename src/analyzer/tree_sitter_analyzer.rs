use crate::analyzer::cognitive_complexity;
use crate::analyzer::persistence::{self, AnalyzerStorage};
use crate::analyzer::{
    AnalyzerConfig, CodeBaseMetrics, CodeUnit, DeclarationInfo, DefinitionLookupIndex, ImportInfo,
    Language, Project, ProjectFile, Range, RubyMethodDispatchMode, SignatureMetadata,
    UsageFactsIndex,
};
use crate::hash::{HashMap, HashSet, map_with_capacity, set_with_capacity};
use crate::profiling;
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
use rayon::prelude::*;
use regex::RegexBuilder;
use std::collections::{BTreeSet, VecDeque};
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tree_sitter::{Language as TsLanguage, Node, Parser, Tree};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WalkControl {
    Continue,
    SkipChildren,
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
    fn is_anonymous_structure(&self, _fq_name: &str) -> bool {
        false
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
    /// `Some` expose `search_ast` support through
    /// [`crate::analyzer::structural::StructuralSearchProvider`].
    fn structural_spec(&self) -> Option<&'static dyn crate::analyzer::structural::StructuralSpec> {
        None
    }
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
pub(crate) struct FileState {
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
    /// persisted baseline (which does not carry parse_errors); the diagnostic
    /// handler falls back to a fresh parse in that case until the next
    /// `update` re-populates the field.
    pub(crate) parse_errors: Option<Vec<crate::analyzer::ParseError>>,
}

#[derive(Debug, Clone, Default)]
struct AnalyzerState {
    files: HashMap<ProjectFile, FileState>,
    definitions: HashMap<String, Vec<CodeUnit>>,
    // Arc so per-query views (e.g. Scala's ProjectTypes) can hold an owned
    // handle without cloning the workspace-sized maps.
    definition_lookup_index: Arc<DefinitionLookupIndex>,
    usage_facts_index: Arc<UsageFactsIndex>,
    // Child lists are canonicalized once while building immutable analyzer
    // state. `direct_children` intentionally exposes this deduped, source-
    // ordered contract; callers only reorder when they need a presentation-
    // specific view such as fields-first skeleton rendering.
    children: HashMap<CodeUnit, Vec<CodeUnit>>,
    module_children: HashMap<String, Vec<CodeUnit>>,
    ranges: HashMap<CodeUnit, Vec<Range>>,
    raw_supertypes: HashMap<CodeUnit, Vec<String>>,
    signatures: HashMap<CodeUnit, Vec<String>>,
    signature_metadata: HashMap<CodeUnit, Vec<SignatureMetadata>>,
    ruby_method_dispatch_modes: HashMap<CodeUnit, RubyMethodDispatchMode>,
    scala_traits: HashSet<CodeUnit>,
    classes_by_package: HashMap<String, Vec<CodeUnit>>,
    #[allow(dead_code)]
    type_aliases: HashSet<CodeUnit>,
}

#[derive(Debug, Default)]
struct IndexCapacities {
    definitions: usize,
    children: usize,
    module_children: usize,
    ranges: usize,
    raw_supertypes: usize,
    signatures: usize,
    signature_metadata: usize,
    ruby_method_dispatch_modes: usize,
    scala_traits: usize,
    classes_by_package: usize,
    type_aliases: usize,
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
    ranges: HashMap<CodeUnit, Vec<Range>>,
    children: HashMap<CodeUnit, Vec<CodeUnit>>,
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
    state: Arc<AnalyzerState>,
    storage: Option<Arc<AnalyzerStorage>>,
    /// Structural-search facts cache (issue #328). Shared across clones and
    /// incremental `update()` generations — entries are validated against a
    /// hash of the current in-memory source, so surviving stale entries are
    /// self-healing rather than wrong.
    structural_cache: Arc<crate::analyzer::structural::provider::StructuralFactsCache>,
    _state: PhantomData<A>,
}

impl<A> Clone for TreeSitterAnalyzer<A> {
    fn clone(&self) -> Self {
        Self {
            project: Arc::clone(&self.project),
            adapter: Arc::clone(&self.adapter),
            config: self.config.clone(),
            state: Arc::clone(&self.state),
            storage: self.storage.as_ref().map(Arc::clone),
            structural_cache: Arc::clone(&self.structural_cache),
            _state: PhantomData,
        }
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

    fn definition_sort_key(
        adapter: &A,
        ranges: &HashMap<CodeUnit, Vec<Range>>,
        code_unit: &CodeUnit,
    ) -> (i32, usize, String, String, String, String) {
        let first_start_byte = ranges
            .get(code_unit)
            .and_then(|entries| entries.iter().map(|range| range.start_byte).min())
            .unwrap_or(usize::MAX);
        (
            adapter.definition_priority(code_unit),
            first_start_byte,
            code_unit.source().to_string().to_ascii_lowercase(),
            code_unit.fq_name().to_ascii_lowercase(),
            code_unit.signature().unwrap_or("").to_ascii_lowercase(),
            format!("{:?}", code_unit.kind()),
        )
    }

    pub fn new(project: Arc<dyn Project>, adapter: A) -> Self {
        Self::new_with_config(project, adapter, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, adapter: A, config: AnalyzerConfig) -> Self {
        Self::new_internal(project, adapter, config, None, None)
    }

    /// Same as `new_with_config` but persists analyzer state to and from
    /// `storage`. On startup the analyzer reads the persisted baseline,
    /// reanalyzes only files whose `(mtime_ns, size)` or epoch differ, and
    /// writes the merged result back in a single transaction.
    pub fn new_with_config_and_storage(
        project: Arc<dyn Project>,
        adapter: A,
        config: AnalyzerConfig,
        storage: Arc<AnalyzerStorage>,
    ) -> Self {
        Self::new_internal(project, adapter, config, None, Some(storage))
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

    pub fn new_with_config_storage_and_progress<F>(
        project: Arc<dyn Project>,
        adapter: A,
        config: AnalyzerConfig,
        storage: Arc<AnalyzerStorage>,
        progress: F,
    ) -> Self
    where
        F: Fn(BuildProgressEvent) + Send + Sync + 'static,
    {
        Self::new_internal(
            project,
            adapter,
            config,
            Some(Arc::new(progress)),
            Some(storage),
        )
    }

    fn new_internal(
        project: Arc<dyn Project>,
        adapter: A,
        config: AnalyzerConfig,
        progress: Option<BuildProgress>,
        storage: Option<Arc<AnalyzerStorage>>,
    ) -> Self {
        let adapter = Arc::new(adapter);
        let state = {
            let _scope = profiling::scope(format!(
                "TreeSitterAnalyzer::{:?}::new_with_config",
                adapter.language()
            ));
            Arc::new(Self::build_state(
                project.as_ref(),
                adapter.as_ref(),
                &config,
                None,
                progress,
                storage.as_deref(),
            ))
        };

        let structural_cache = Arc::new(Self::build_structural_cache(&config));
        Self {
            project,
            adapter,
            config,
            state,
            storage,
            structural_cache,
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
        state: AnalyzerState,
        storage: Option<Arc<AnalyzerStorage>>,
        structural_cache: Arc<crate::analyzer::structural::provider::StructuralFactsCache>,
    ) -> Self {
        Self {
            project,
            adapter,
            config,
            state: Arc::new(state),
            storage,
            structural_cache,
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

        if let Some(parent) = self.state.children.iter().find_map(|(parent, children)| {
            if children.iter().any(|child| child == code_unit) {
                Some(parent.clone())
            } else {
                None
            }
        }) {
            return Some(parent);
        }

        for (module_name, children) in &self.state.module_children {
            if !children.iter().any(|child| child == code_unit) {
                continue;
            }
            if let Some(parent) = self
                .state
                .files
                .values()
                .flat_map(|state| state.declarations.iter())
                .find(|unit| {
                    unit.is_module()
                        && self.adapter.normalize_full_name(&unit.fq_name()) == *module_name
                })
            {
                return Some(parent.clone());
            }
        }

        None
    }

    pub fn top_level_file_scope_parent_of(&self, code_unit: &CodeUnit) -> Option<CodeUnit> {
        if code_unit.is_module() {
            return None;
        }

        let state = self.state.files.get(code_unit.source())?;
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

    fn build_state(
        project: &dyn Project,
        adapter: &A,
        config: &AnalyzerConfig,
        existing: Option<&AnalyzerState>,
        progress: Option<BuildProgress>,
        storage: Option<&AnalyzerStorage>,
    ) -> AnalyzerState {
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
        let analyzable_set: HashSet<_> = analyzable_files.iter().cloned().collect();

        // Decide reconcile partition.
        let storage_epoch: Option<&'static str> = storage.map(|_| {
            let ts_lang = adapter.parser_language();
            persistence::epoch_for(adapter.language(), &ts_lang)
        });

        let (mut files, dirty_files, mut deletes, epoch_for_commit) = match (storage, storage_epoch)
        {
            (Some(storage), Some(epoch_now)) => match persistence::reconcile::plan(
                storage,
                adapter.language(),
                epoch_now,
                &analyzable_files,
            ) {
                Ok(plan) => {
                    if let Some(progress) = progress.as_ref() {
                        progress(BuildProgressEvent::new(
                            adapter.language(),
                            BuildProgressPhase::Reconcile,
                            plan.clean_hydrated.len(),
                            analyzable_files.len(),
                            None,
                        ));
                    }
                    (
                        plan.clean_hydrated,
                        plan.dirty_to_analyze,
                        plan.deletes,
                        Some(epoch_now),
                    )
                }
                Err(_) => {
                    // Storage failed (corrupt, locked, etc.). Fall back to a
                    // full in-memory rebuild so the analyzer still produces
                    // results; persistence is best-effort.
                    (
                        HashMap::default(),
                        analyzable_files.clone(),
                        Vec::new(),
                        None,
                    )
                }
            },
            _ => {
                let mut files = existing
                    .map(|state| state.files.clone())
                    .unwrap_or_default();
                files.retain(|file, _| analyzable_set.contains(file));
                let dirty: Vec<_> = analyzable_files.clone();
                (files, dirty, Vec::new(), None)
            }
        };

        let dirty_keys: HashSet<ProjectFile> = dirty_files.iter().cloned().collect();
        let storage_active = epoch_for_commit.is_some();

        for (file, state) in
            Self::analyze_files(adapter, project, config, dirty_files, progress.clone())
        {
            if let Some(state) = state {
                files.insert(file, state);
            } else {
                // Parse failure for a workspace file: drop any in-memory
                // entry AND tell the storage commit to delete the matching
                // baseline row, so a stale payload from a previous epoch
                // can't be hydrated next startup.
                if storage_active {
                    deletes.push(persistence::reconcile::rel_key(&file));
                }
                files.remove(&file);
            }
        }

        if let (Some(storage), Some(epoch)) = (storage, epoch_for_commit) {
            // Skip baseline writes for files whose parsed state was computed
            // against an in-memory overlay — the on-disk mtime did not change,
            // so a baseline row would mis-hydrate the next session.
            let writes = persistence::reconcile::encode_writes(
                files
                    .iter()
                    .filter(|(file, _)| dirty_keys.contains(file))
                    .filter(|(file, _)| !project.has_overlay(file)),
                |fq_name| adapter.normalize_full_name(fq_name),
            );
            // Persistence is best-effort; a write failure should not poison
            // the in-memory analyzer.
            let _ = persistence::reconcile::commit(
                storage,
                adapter.language(),
                epoch,
                &writes,
                &deletes,
            );
            if let Some(progress) = progress.as_ref() {
                let total = writes.len() + deletes.len();
                progress(BuildProgressEvent::new(
                    adapter.language(),
                    BuildProgressPhase::Persist,
                    total,
                    total,
                    None,
                ));
            }
        }

        {
            let _scope = profiling::scope(format!(
                "TreeSitterAnalyzer::{:?}::index_state",
                adapter.language()
            ));
            if let Some(progress) = progress.as_ref() {
                progress(BuildProgressEvent::new(
                    adapter.language(),
                    BuildProgressPhase::Index,
                    files.len(),
                    files.len(),
                    None,
                ));
            }
            Self::index_state(files, project, adapter)
        }
    }

    fn index_state(
        files: HashMap<ProjectFile, FileState>,
        project: &dyn Project,
        adapter: &A,
    ) -> AnalyzerState {
        // The immutable index merges every per-file declaration table once; pre-sizing
        // these maps avoids repeated growth while building large workspaces.
        let capacities = Self::index_capacities(&files);
        let mut definitions = map_with_capacity::<String, Vec<CodeUnit>>(capacities.definitions);
        let mut definition_lookup_index = DefinitionLookupIndex::default();
        let mut children = map_with_capacity::<CodeUnit, Vec<CodeUnit>>(capacities.children);
        let mut module_children =
            map_with_capacity::<String, Vec<CodeUnit>>(capacities.module_children);
        let mut ranges = map_with_capacity::<CodeUnit, Vec<Range>>(capacities.ranges);
        let mut raw_supertypes =
            map_with_capacity::<CodeUnit, Vec<String>>(capacities.raw_supertypes);
        let mut signatures = map_with_capacity::<CodeUnit, Vec<String>>(capacities.signatures);
        let mut signature_metadata =
            map_with_capacity::<CodeUnit, Vec<SignatureMetadata>>(capacities.signature_metadata);
        let mut ruby_method_dispatch_modes = map_with_capacity::<CodeUnit, RubyMethodDispatchMode>(
            capacities.ruby_method_dispatch_modes,
        );
        let mut scala_traits = set_with_capacity::<CodeUnit>(capacities.scala_traits);
        let mut classes_by_package =
            map_with_capacity::<String, Vec<CodeUnit>>(capacities.classes_by_package);
        let mut type_aliases = set_with_capacity::<CodeUnit>(capacities.type_aliases);

        for state in files.values() {
            for declaration in &state.declarations {
                if !declaration.is_file_scope() {
                    definition_lookup_index.insert(
                        declaration,
                        &|fq_name| adapter.normalize_full_name(fq_name),
                        &|unit| adapter.simple_type_name(unit),
                    );
                    definitions
                        .entry(adapter.normalize_full_name(&declaration.fq_name()))
                        .or_default()
                        .push(declaration.clone());
                }
                if declaration.is_class() {
                    classes_by_package
                        .entry(declaration.package_name().to_string())
                        .or_default()
                        .push(declaration.clone());
                }
            }
            for lookup_unit in &state.definition_lookup_units {
                definition_lookup_index.insert(
                    lookup_unit,
                    &|fq_name| adapter.normalize_full_name(fq_name),
                    &|unit| adapter.simple_type_name(unit),
                );
            }

            for (parent, descendants) in &state.children {
                children
                    .entry(parent.clone())
                    .or_default()
                    .extend(descendants.iter().cloned());
            }

            for (code_unit, code_unit_ranges) in &state.ranges {
                ranges
                    .entry(code_unit.clone())
                    .or_default()
                    .extend(code_unit_ranges.iter().copied());
            }

            for (code_unit, raw) in &state.raw_supertypes {
                raw_supertypes.insert(code_unit.clone(), raw.clone());
            }

            for (code_unit, sigs) in &state.signatures {
                signatures
                    .entry(code_unit.clone())
                    .or_default()
                    .extend(sigs.iter().cloned());
            }

            for (code_unit, metadata) in &state.signature_metadata {
                signature_metadata
                    .entry(code_unit.clone())
                    .or_default()
                    .extend(metadata.iter().cloned());
            }

            ruby_method_dispatch_modes.extend(
                state
                    .ruby_method_dispatch_modes
                    .iter()
                    .map(|(unit, mode)| (unit.clone(), *mode)),
            );

            scala_traits.extend(state.scala_traits.iter().cloned());
            type_aliases.extend(state.type_aliases.iter().cloned());
        }

        for (parent, descendants) in children.iter_mut() {
            Self::canonicalize_children(descendants, &ranges);
            if parent.is_module() {
                module_children
                    .entry(adapter.normalize_full_name(&parent.fq_name()))
                    .or_default()
                    .extend(descendants.iter().cloned());
            }
        }

        for descendants in module_children.values_mut() {
            Self::canonicalize_children(descendants, &ranges);
        }

        for matches in definitions.values_mut() {
            matches.sort_by_cached_key(|code_unit| {
                Self::definition_sort_key(adapter, &ranges, code_unit)
            });
            matches.dedup();
        }
        definition_lookup_index.sort_entries();

        for matches in classes_by_package.values_mut() {
            matches.sort_by_cached_key(|code_unit| {
                Self::definition_sort_key(adapter, &ranges, code_unit)
            });
            matches.dedup();
        }

        let _ = project;
        let usage_facts_index = UsageFactsIndex::build_from_declarations(
            &definition_lookup_index,
            files.values().flat_map(|state| state.declarations.iter()),
            |unit| {
                signatures
                    .get(unit)
                    .and_then(|entries| entries.first().cloned())
                    .or_else(|| unit.signature().map(str::to_string))
            },
            |unit| {
                signature_metadata
                    .get(unit)
                    .and_then(|entries| entries.first().cloned())
            },
            adapter,
        );

        AnalyzerState {
            files,
            definitions,
            definition_lookup_index: Arc::new(definition_lookup_index),
            usage_facts_index: Arc::new(usage_facts_index),
            children,
            module_children,
            ranges,
            raw_supertypes,
            signatures,
            signature_metadata,
            ruby_method_dispatch_modes,
            scala_traits,
            classes_by_package,
            type_aliases,
        }
    }

    fn index_capacities(files: &HashMap<ProjectFile, FileState>) -> IndexCapacities {
        let mut capacities = IndexCapacities::default();
        let mut class_declarations = 0usize;

        for state in files.values() {
            capacities.definitions += state.declarations.len();
            capacities.children += state.children.len();
            capacities.module_children += state
                .children
                .keys()
                .filter(|parent| parent.is_module())
                .count();
            capacities.ranges += state.ranges.len();
            capacities.raw_supertypes += state.raw_supertypes.len();
            capacities.signatures += state.signatures.len();
            capacities.signature_metadata += state.signature_metadata.len();
            capacities.ruby_method_dispatch_modes += state.ruby_method_dispatch_modes.len();
            capacities.scala_traits += state.scala_traits.len();
            capacities.type_aliases += state.type_aliases.len();
            class_declarations += state
                .declarations
                .iter()
                .filter(|declaration| declaration.is_class())
                .count();
        }

        capacities.classes_by_package = class_declarations.min(files.len());
        capacities
    }

    fn file_state(&self, file: &ProjectFile) -> Option<&FileState> {
        self.state.files.get(file)
    }

    /// The retained source text of an analyzed file. Structural search
    /// re-parses from this instead of touching disk.
    pub(crate) fn file_source(&self, file: &ProjectFile) -> Option<&str> {
        self.file_state(file).map(|state| state.source.as_str())
    }

    pub(crate) fn package_name_of(&self, file: &ProjectFile) -> Option<&str> {
        self.file_state(file)
            .map(|state| state.package_name.as_str())
    }

    pub(crate) fn ruby_method_dispatch_mode(
        &self,
        code_unit: &CodeUnit,
    ) -> Option<RubyMethodDispatchMode> {
        self.state
            .ruby_method_dispatch_modes
            .get(code_unit)
            .copied()
    }

    pub(crate) fn import_info_of<'a>(&'a self, file: &ProjectFile) -> &'a [ImportInfo] {
        self.file_state(file)
            .map(|state| state.imports.as_slice())
            .unwrap_or(&[])
    }

    pub(crate) fn raw_supertypes_of<'a>(&'a self, code_unit: &CodeUnit) -> &'a [String] {
        self.state
            .raw_supertypes
            .get(code_unit)
            .map(Vec::as_slice)
            .or_else(|| {
                self.file_state(code_unit.source())
                    .and_then(|state| state.raw_supertypes.get(code_unit).map(Vec::as_slice))
            })
            .unwrap_or(&[])
    }

    pub(crate) fn is_scala_trait(&self, code_unit: &CodeUnit) -> bool {
        self.state.scala_traits.contains(code_unit)
            || self
                .file_state(code_unit.source())
                .is_some_and(|state| state.scala_traits.contains(code_unit))
    }

    pub(crate) fn scala_traits<'a>(&'a self) -> impl Iterator<Item = &'a CodeUnit> + 'a {
        self.state.scala_traits.iter()
    }

    pub(crate) fn type_identifiers_of(&self, file: &ProjectFile) -> Option<&HashSet<String>> {
        self.file_state(file).map(|state| &state.type_identifiers)
    }

    pub(crate) fn all_files<'a>(&'a self) -> impl Iterator<Item = &'a ProjectFile> + 'a {
        self.state.files.keys()
    }

    pub(crate) fn class_declarations_in_package<'a>(
        &'a self,
        package_name: &str,
    ) -> &'a [CodeUnit] {
        self.state
            .classes_by_package
            .get(package_name)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    #[allow(dead_code)]
    pub(crate) fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
        self.state.type_aliases.contains(code_unit)
    }

    pub(crate) fn signatures_of<'a>(&'a self, code_unit: &CodeUnit) -> &'a [String] {
        self.state
            .signatures
            .get(code_unit)
            .map(Vec::as_slice)
            .or_else(|| {
                self.file_state(code_unit.source())
                    .and_then(|state| state.signatures.get(code_unit).map(Vec::as_slice))
            })
            .unwrap_or(&[])
    }

    pub(crate) fn signature_metadata_of<'a>(
        &'a self,
        code_unit: &CodeUnit,
    ) -> &'a [SignatureMetadata] {
        self.state
            .signature_metadata
            .get(code_unit)
            .map(Vec::as_slice)
            .or_else(|| {
                self.file_state(code_unit.source())
                    .and_then(|state| state.signature_metadata.get(code_unit).map(Vec::as_slice))
            })
            .unwrap_or(&[])
    }

    fn source_slice(
        &self,
        code_unit: &CodeUnit,
        range: &Range,
        include_comments: bool,
    ) -> Option<String> {
        let file_state = self.file_state(code_unit.source())?;
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
        for signature in self.signatures_of(code_unit) {
            if signature.is_empty() {
                continue;
            }
            for line in signature.lines() {
                out.push_str(indent);
                out.push_str(line);
                out.push('\n');
            }
        }

        let all_children: Vec<_> = crate::analyzer::IAnalyzer::direct_children(self, code_unit)
            .filter(|child| {
                !child.is_synthetic() || !crate::analyzer::IAnalyzer::ranges(self, child).is_empty()
            })
            .collect();
        let field_children: Vec<_> = all_children
            .iter()
            .copied()
            .filter(|child| child.is_field())
            .collect();
        let parent_start = crate::analyzer::IAnalyzer::ranges(self, code_unit)
            .iter()
            .map(|range| range.start_byte)
            .min()
            .unwrap_or(usize::MAX);
        let non_field_children: Vec<_> = all_children
            .iter()
            .copied()
            .filter(|child| !child.is_field())
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
                .copied()
                .collect()
        };

        if !children.is_empty() || code_unit.is_class() {
            let child_indent = format!("{indent}  ");
            for child in children {
                self.render_skeleton_recursive(child, &child_indent, header_only, out);
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
        crate::analyzer::IAnalyzer::ranges(self, child)
            .iter()
            .map(|range| range.start_byte)
            .min()
            .unwrap_or(usize::MAX)
    }

    /// Owned handle to the workspace definition index. A refcount bump, not a
    /// map clone; used by per-query views that must outlive a borrow of the
    /// analyzer (e.g. Scala's `ProjectTypes` behind `Arc` caches).
    pub(crate) fn definition_lookup_index_shared(&self) -> Arc<DefinitionLookupIndex> {
        Arc::clone(&self.state.definition_lookup_index)
    }

    /// Owned handle to the derived callable-facts index; see
    /// [`Self::definition_lookup_index_shared`].
    pub(crate) fn usage_facts_index_shared(&self) -> Arc<UsageFactsIndex> {
        Arc::clone(&self.state.usage_facts_index)
    }
}

impl<A> crate::analyzer::IAnalyzer for TreeSitterAnalyzer<A>
where
    A: LanguageAdapter,
{
    fn top_level_declarations<'a>(
        &'a self,
        file: &ProjectFile,
    ) -> Box<dyn Iterator<Item = &'a CodeUnit> + 'a> {
        match self.file_state(file) {
            Some(state) => Box::new(
                state
                    .top_level_declarations
                    .iter()
                    .filter(|code_unit| !code_unit.is_file_scope()),
            ),
            None => Box::new(std::iter::empty()),
        }
    }

    fn analyzed_files<'a>(&'a self) -> Box<dyn Iterator<Item = &'a ProjectFile> + 'a> {
        Box::new(self.state.files.keys())
    }

    fn is_analyzed(&self, file: &ProjectFile) -> bool {
        self.state.files.contains_key(file)
    }

    fn languages(&self) -> BTreeSet<Language> {
        BTreeSet::from([self.adapter.language()])
    }

    fn update(&self, changed_files: &BTreeSet<ProjectFile>) -> Self {
        if changed_files.is_empty() {
            return self.clone();
        }

        let mut files = self.state.files.clone();
        let mut to_reanalyze = Vec::new();
        let mut deletes: Vec<String> = Vec::new();

        for file in changed_files {
            if !file.exists() {
                files.remove(file);
                deletes.push(persistence::reconcile::rel_key(file));
                continue;
            }
            to_reanalyze.push(file.clone());
        }

        let dirty_keys: HashSet<ProjectFile> = to_reanalyze.iter().cloned().collect();

        for (file, state) in Self::analyze_files(
            self.adapter.as_ref(),
            self.project.as_ref(),
            &self.config,
            to_reanalyze,
            None,
        ) {
            if let Some(state) = state {
                files.insert(file, state);
            } else {
                deletes.push(persistence::reconcile::rel_key(&file));
                files.remove(&file);
            }
        }

        if let Some(storage) = self.storage.as_ref() {
            let ts_lang = self.adapter.parser_language();
            let epoch = persistence::epoch_for(self.adapter.language(), &ts_lang);
            let project = self.project.as_ref();
            // Skip baseline writes for overlaid files; see build_state.
            let writes = persistence::reconcile::encode_writes(
                files
                    .iter()
                    .filter(|(file, _)| dirty_keys.contains(file))
                    .filter(|(file, _)| !project.has_overlay(file)),
                |fq_name| self.adapter.normalize_full_name(fq_name),
            );
            let _ = persistence::reconcile::commit(
                storage.as_ref(),
                self.adapter.language(),
                epoch,
                &writes,
                &deletes,
            );
        }

        let state = Self::index_state(files, self.project.as_ref(), self.adapter.as_ref());
        Self::from_state(
            Arc::clone(&self.project),
            Arc::clone(&self.adapter),
            self.config.clone(),
            state,
            self.storage.as_ref().map(Arc::clone),
            Arc::clone(&self.structural_cache),
        )
    }

    fn update_all(&self) -> Self {
        let state = Self::build_state(
            self.project.as_ref(),
            self.adapter.as_ref(),
            &self.config,
            None,
            None,
            self.storage.as_deref(),
        );
        Self::from_state(
            Arc::clone(&self.project),
            Arc::clone(&self.adapter),
            self.config.clone(),
            state,
            self.storage.as_ref().map(Arc::clone),
            Arc::clone(&self.structural_cache),
        )
    }

    fn project(&self) -> &dyn Project {
        self.project()
    }

    fn all_declarations<'a>(&'a self) -> Box<dyn Iterator<Item = &'a CodeUnit> + 'a> {
        Box::new(
            self.state
                .files
                .values()
                .flat_map(|state| state.declarations.iter())
                .filter(|unit| !unit.is_file_scope()),
        )
    }

    fn declarations<'a>(
        &'a self,
        file: &ProjectFile,
    ) -> Box<dyn Iterator<Item = &'a CodeUnit> + 'a> {
        match self.file_state(file) {
            Some(state) => Box::new(
                state
                    .declarations
                    .iter()
                    .filter(|unit| !unit.is_file_scope()),
            ),
            None => Box::new(std::iter::empty()),
        }
    }

    fn definitions<'a>(&'a self, fq_name: &'a str) -> Box<dyn Iterator<Item = &'a CodeUnit> + 'a> {
        let normalized = self.adapter.normalize_full_name(fq_name);
        let Some(matches) = self.state.definitions.get(&normalized) else {
            return Box::new(std::iter::empty());
        };
        Box::new(
            matches
                .iter()
                .scan(false, |saw_module, code_unit| {
                    if code_unit.is_module() {
                        if *saw_module {
                            Some(None)
                        } else {
                            *saw_module = true;
                            Some(Some(code_unit))
                        }
                    } else {
                        Some(Some(code_unit))
                    }
                })
                .flatten(),
        )
    }

    fn definition_lookup_index(&self) -> &DefinitionLookupIndex {
        &self.state.definition_lookup_index
    }

    fn usage_facts_index(&self) -> &UsageFactsIndex {
        &self.state.usage_facts_index
    }

    fn direct_children<'a>(
        &'a self,
        code_unit: &CodeUnit,
    ) -> Box<dyn Iterator<Item = &'a CodeUnit> + 'a> {
        if code_unit.is_module() {
            let target_name = self.adapter.normalize_full_name(&code_unit.fq_name());
            match self.state.module_children.get(&target_name) {
                Some(children) => Box::new(children.iter()),
                None => Box::new(std::iter::empty()),
            }
        } else {
            match self.state.children.get(code_unit) {
                Some(children) => Box::new(children.iter()),
                None => Box::new(std::iter::empty()),
            }
        }
    }

    fn parse_errors(&self, file: &ProjectFile) -> Option<Vec<crate::analyzer::ParseError>> {
        self.file_state(file)
            .and_then(|state| state.parse_errors.clone())
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        self.adapter.extract_call_receiver(reference)
    }

    fn import_statements<'a>(&'a self, file: &ProjectFile) -> &'a [String] {
        self.file_state(file)
            .map(|state| state.import_statements.as_slice())
            .unwrap_or(&[])
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

        self.file_state(file)?
            .declarations
            .iter()
            .filter_map(|code_unit| {
                let best_range = self
                    .ranges(code_unit)
                    .iter()
                    .find(|candidate| candidate.contains(range))?;
                Some((
                    best_range.end_byte - best_range.start_byte,
                    code_unit.clone(),
                ))
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
            .filter_map(|code_unit| {
                let best_range = self.ranges(code_unit).iter().find(|candidate| {
                    candidate.start_line <= line_range.start_line
                        && candidate.end_line >= line_range.end_line
                })?;
                Some((
                    best_range.end_line - best_range.start_line,
                    code_unit.clone(),
                ))
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

    fn ranges<'a>(&'a self, code_unit: &CodeUnit) -> &'a [Range] {
        self.state
            .ranges
            .get(code_unit)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    fn compute_cognitive_complexities(&self, file: &ProjectFile) -> Vec<(CodeUnit, u32)> {
        let Some(config) = self.adapter.cognitive_complexity_config() else {
            return Vec::new();
        };
        let Some(file_state) = self.file_state(file) else {
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
            if let Some(children) = self.state.children.get(&cu) {
                for child in children {
                    work.push_back(child.clone());
                }
            } else if let Some(file_children) = file_state.children.get(&cu) {
                for child in file_children {
                    work.push_back(child.clone());
                }
            }
        }

        let mut result = Vec::with_capacity(functions.len());
        for cu in functions {
            let Some(ranges) = self.state.ranges.get(&cu) else {
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
                    grouped.extend(self.ranges(candidate).iter().copied());
                }
            }
            grouped
        } else {
            self.ranges(code_unit).to_vec()
        };

        ranges.sort_by_key(|range| range.start_byte);
        ranges
            .into_iter()
            .filter_map(|range| self.source_slice(code_unit, &range, include_comments))
            .collect()
    }

    fn search_definitions(&self, pattern: &str, auto_quote: bool) -> BTreeSet<CodeUnit> {
        if pattern.is_empty() {
            return BTreeSet::new();
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

        let Ok(compiled) = RegexBuilder::new(&pattern).case_insensitive(true).build() else {
            return BTreeSet::new();
        };

        self.state
            .definitions
            .par_iter()
            .filter(|(fq_name, _)| {
                !self.adapter.is_anonymous_structure(fq_name) && compiled.is_match(fq_name)
            })
            .flat_map(|(_, definitions)| definitions.to_vec())
            .collect()
    }

    fn search_definitions_persisted(&self, pattern: &str) -> BTreeSet<CodeUnit> {
        if pattern.is_empty() {
            return BTreeSet::new();
        }
        let Some(storage) = self.storage.as_ref() else {
            return self.search_definitions(pattern, true);
        };
        // FTS5's trigram tokenizer produces no tokens for inputs shorter
        // than three characters, so any 1- or 2-char query against the
        // substring index returns zero rows regardless of what's
        // indexed. The in-memory regex search has no such floor, so for
        // short patterns we fall back to it to preserve substring
        // semantics.
        if pattern.chars().count() < 3 {
            return self.search_definitions(pattern, true);
        }
        let language = self.adapter.language();
        // The trigram index models the same substring semantics the
        // existing in-memory `search_definitions` provides, so callers
        // who switch to the persisted variant don't see a regression in
        // recall. The unicode61 token index is reserved for future
        // identifier-only / FQN-token query paths.
        //
        // `search_non_synthetic_symbols` pushes the synthetic filter
        // into SQL so it runs before `LIMIT` — otherwise a top-N cap
        // can be entirely consumed by compiler-generated rows that the
        // post-filter below would drop anyway.
        let hits = match storage.search_non_synthetic_symbols(
            language,
            pattern,
            persistence::SymbolQueryMode::Substring,
        ) {
            Ok(hits) => hits,
            Err(_) => return self.search_definitions(pattern, true),
        };
        let mut out = BTreeSet::new();
        let project_root = self.project.root().to_path_buf();
        for hit in hits {
            if self.adapter.is_anonymous_structure(&hit.symbol.fq_name) {
                continue;
            }
            let Some(kind) = persistence::parse_kind(&hit.symbol.kind) else {
                continue;
            };
            let rel_path = std::path::PathBuf::from(&hit.rel_path);
            let source = ProjectFile::new(project_root.clone(), rel_path);
            out.insert(CodeUnit::with_signature(
                source,
                kind,
                hit.symbol.package_name,
                hit.symbol.short_name,
                hit.symbol.signature,
                hit.symbol.synthetic,
            ));
        }
        out
    }

    fn metrics(&self) -> CodeBaseMetrics {
        CodeBaseMetrics::new(
            self.state.files.len(),
            self.state
                .files
                .values()
                .map(|state| {
                    state
                        .declarations
                        .iter()
                        .filter(|unit| !unit.is_file_scope())
                        .count()
                })
                .sum(),
        )
    }

    fn contains_tests(&self, file: &ProjectFile) -> bool {
        self.file_state(file)
            .map(|state| state.contains_tests)
            .unwrap_or(false)
    }

    fn signatures<'a>(&'a self, code_unit: &CodeUnit) -> &'a [String] {
        self.signatures_of(code_unit)
    }

    fn signature_metadata<'a>(&'a self, code_unit: &CodeUnit) -> &'a [SignatureMetadata] {
        self.signature_metadata_of(code_unit)
    }
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

    fn parse_javascript(source: &str) -> Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .expect("javascript parser");
        parser.parse(source, None).expect("parse javascript")
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
}
