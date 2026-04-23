use crate::analyzer::{
    AnalyzerConfig, CodeBaseMetrics, CodeUnit, DeclarationInfo, ImportInfo, Language, Project,
    ProjectFile, Range,
};
use crate::hash::{HashMap, HashSet, map_with_capacity, set_with_capacity};
use crate::profiling;
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
use rayon::prelude::*;
use regex::RegexBuilder;
use std::collections::BTreeSet;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tree_sitter::{Language as TsLanguage, Node, Parser, Tree};

pub trait LanguageAdapter: Send + Sync + 'static {
    fn language(&self) -> Language;
    fn query_directory(&self) -> &'static str;
    fn parser_language(&self) -> TsLanguage;
    fn file_extension(&self) -> &'static str;
    fn normalize_full_name(&self, fq_name: &str) -> String {
        fq_name.to_string()
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
}

type BuildProgress = Arc<dyn Fn(usize, usize, &ProjectFile) + Send + Sync>;

#[derive(Debug, Clone)]
struct FileState {
    source: String,
    package_name: String,
    top_level_declarations: Vec<CodeUnit>,
    declarations: HashSet<CodeUnit>,
    import_statements: Vec<String>,
    imports: Vec<ImportInfo>,
    raw_supertypes: HashMap<CodeUnit, Vec<String>>,
    type_identifiers: HashSet<String>,
    signatures: HashMap<CodeUnit, Vec<String>>,
    ranges: HashMap<CodeUnit, Vec<Range>>,
    children: HashMap<CodeUnit, Vec<CodeUnit>>,
    type_aliases: HashSet<CodeUnit>,
    contains_tests: bool,
}

#[derive(Debug, Clone, Default)]
struct AnalyzerState {
    files: HashMap<ProjectFile, FileState>,
    definitions: HashMap<String, Vec<CodeUnit>>,
    // Child lists are canonicalized once while building immutable analyzer
    // state. `direct_children` intentionally exposes this deduped, source-
    // ordered contract; callers only reorder when they need a presentation-
    // specific view such as fields-first skeleton rendering.
    children: HashMap<CodeUnit, Vec<CodeUnit>>,
    module_children: HashMap<String, Vec<CodeUnit>>,
    ranges: HashMap<CodeUnit, Vec<Range>>,
    raw_supertypes: HashMap<CodeUnit, Vec<String>>,
    signatures: HashMap<CodeUnit, Vec<String>>,
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
    classes_by_package: usize,
    type_aliases: usize,
}

#[derive(Debug, Clone)]
pub struct ParsedFile {
    pub package_name: String,
    pub top_level_declarations: Vec<CodeUnit>,
    pub declarations: HashSet<CodeUnit>,
    pub import_statements: Vec<String>,
    pub imports: Vec<ImportInfo>,
    pub raw_supertypes: HashMap<CodeUnit, Vec<String>>,
    pub type_identifiers: HashSet<String>,
    pub signatures: HashMap<CodeUnit, Vec<String>>,
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
            import_statements: Vec::new(),
            imports: Vec::new(),
            raw_supertypes: HashMap::default(),
            type_identifiers: HashSet::default(),
            signatures: HashMap::default(),
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
        if parent.is_none() {
            self.top_level_declarations.push(code_unit.clone());
        }

        self.declarations.insert(code_unit.clone());
        self.ranges
            .entry(code_unit.clone())
            .or_default()
            .push(node_range(node));

        if let Some(parent) = parent {
            self.children
                .entry(parent)
                .or_default()
                .push(code_unit.clone());
        }

        if let Some(top_level) = top_level {
            self.children.entry(top_level).or_default();
        }
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

    pub fn add_child(&mut self, parent: CodeUnit, child: CodeUnit) {
        self.children.entry(parent).or_default().push(child);
    }

    pub fn mark_type_alias(&mut self, code_unit: CodeUnit) {
        self.type_aliases.insert(code_unit);
    }

    pub fn set_primary_range(&mut self, code_unit: &CodeUnit, range: Range) {
        self.ranges.insert(code_unit.clone(), vec![range]);
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
        self.raw_supertypes.remove(code_unit);
        self.signatures.remove(code_unit);
        self.type_aliases.remove(code_unit);
        self.ranges.remove(code_unit);
    }
}

pub struct TreeSitterAnalyzer<A> {
    project: Arc<dyn Project>,
    adapter: Arc<A>,
    config: AnalyzerConfig,
    state: Arc<AnalyzerState>,
    _state: PhantomData<A>,
}

impl<A> Clone for TreeSitterAnalyzer<A> {
    fn clone(&self) -> Self {
        Self {
            project: Arc::clone(&self.project),
            adapter: Arc::clone(&self.adapter),
            config: self.config.clone(),
            state: Arc::clone(&self.state),
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
                None,
            ))
        };

        Self {
            project,
            adapter,
            config,
            state,
            _state: PhantomData,
        }
    }

    pub fn new_with_progress<F>(project: Arc<dyn Project>, adapter: A, progress: F) -> Self
    where
        F: Fn(usize, usize, &ProjectFile) + Send + Sync + 'static,
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
        F: Fn(usize, usize, &ProjectFile) + Send + Sync + 'static,
    {
        let adapter = Arc::new(adapter);
        let state = Arc::new(Self::build_state(
            project.as_ref(),
            adapter.as_ref(),
            &config,
            None,
            Some(Arc::new(progress)),
        ));

        Self {
            project,
            adapter,
            config,
            state,
            _state: PhantomData,
        }
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
    ) -> Self {
        Self {
            project,
            adapter,
            config,
            state: Arc::new(state),
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

    fn analyze_file(parser: &mut Parser, adapter: &A, file: &ProjectFile) -> Option<FileState> {
        let bytes = std::fs::read(file.abs_path()).ok()?;
        if bytes.contains(&0) {
            return None;
        }

        let source = String::from_utf8(bytes).ok()?;
        let tree = parser.parse(source.as_str(), None)?;
        let parsed = adapter.parse_file(file, &source, &tree);
        let contains_tests = adapter.contains_tests(file, &source, &tree, &parsed);

        Some(FileState {
            source,
            package_name: parsed.package_name,
            top_level_declarations: parsed.top_level_declarations,
            declarations: parsed.declarations,
            import_statements: parsed.import_statements,
            imports: parsed.imports,
            raw_supertypes: parsed.raw_supertypes,
            type_identifiers: parsed.type_identifiers,
            signatures: parsed.signatures,
            ranges: parsed.ranges,
            children: parsed.children,
            type_aliases: parsed.type_aliases,
            contains_tests,
        })
    }

    fn analyze_files(
        adapter: &A,
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

        let analyzed = pool.install(|| {
            files
                .into_par_iter()
                .map_init(
                    || Self::build_parser(language.clone()),
                    |parser, file| {
                        let state = Self::analyze_file(parser, adapter, &file);
                        if let Some(progress) = progress.as_ref() {
                            let current = completed.fetch_add(1, Ordering::Relaxed) + 1;
                            progress(current, total, &file);
                        }
                        (file, state)
                    },
                )
                .collect::<Vec<_>>()
        });
        analyzed
    }

    fn build_state(
        project: &dyn Project,
        adapter: &A,
        config: &AnalyzerConfig,
        existing: Option<&AnalyzerState>,
        progress: Option<BuildProgress>,
    ) -> AnalyzerState {
        let _scope = profiling::scope(format!(
            "TreeSitterAnalyzer::{:?}::build_state",
            adapter.language()
        ));
        let mut files = existing
            .map(|state| state.files.clone())
            .unwrap_or_default();

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
        let analyzable_set: HashSet<_> = analyzable_files.iter().cloned().collect();

        files.retain(|file, _| analyzable_set.contains(file));

        for (file, state) in Self::analyze_files(adapter, config, analyzable_files, progress) {
            if let Some(state) = state {
                files.insert(file, state);
            } else {
                files.remove(&file);
            }
        }

        {
            let _scope = profiling::scope(format!(
                "TreeSitterAnalyzer::{:?}::index_state",
                adapter.language()
            ));
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
        let mut children = map_with_capacity::<CodeUnit, Vec<CodeUnit>>(capacities.children);
        let mut module_children =
            map_with_capacity::<String, Vec<CodeUnit>>(capacities.module_children);
        let mut ranges = map_with_capacity::<CodeUnit, Vec<Range>>(capacities.ranges);
        let mut raw_supertypes =
            map_with_capacity::<CodeUnit, Vec<String>>(capacities.raw_supertypes);
        let mut signatures = map_with_capacity::<CodeUnit, Vec<String>>(capacities.signatures);
        let mut classes_by_package =
            map_with_capacity::<String, Vec<CodeUnit>>(capacities.classes_by_package);
        let mut type_aliases = set_with_capacity::<CodeUnit>(capacities.type_aliases);

        for state in files.values() {
            for declaration in &state.declarations {
                definitions
                    .entry(adapter.normalize_full_name(&declaration.fq_name()))
                    .or_default()
                    .push(declaration.clone());
                if declaration.is_class() {
                    classes_by_package
                        .entry(declaration.package_name().to_string())
                        .or_default()
                        .push(declaration.clone());
                }
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

        for matches in classes_by_package.values_mut() {
            matches.sort_by_cached_key(|code_unit| {
                Self::definition_sort_key(adapter, &ranges, code_unit)
            });
            matches.dedup();
        }

        let _ = project;

        AnalyzerState {
            files,
            definitions,
            children,
            module_children,
            ranges,
            raw_supertypes,
            signatures,
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

    pub(crate) fn package_name_of(&self, file: &ProjectFile) -> Option<&str> {
        self.file_state(file)
            .map(|state| state.package_name.as_str())
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

        let all_children: Vec<_> =
            crate::analyzer::IAnalyzer::direct_children(self, code_unit).collect();
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
            Some(state) => Box::new(state.top_level_declarations.iter()),
            None => Box::new(std::iter::empty()),
        }
    }

    fn analyzed_files<'a>(&'a self) -> Box<dyn Iterator<Item = &'a ProjectFile> + 'a> {
        Box::new(self.state.files.keys())
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

        for file in changed_files {
            if !file.exists() {
                files.remove(file);
                continue;
            }
            to_reanalyze.push(file.clone());
        }

        for (file, state) in
            Self::analyze_files(self.adapter.as_ref(), &self.config, to_reanalyze, None)
        {
            if let Some(state) = state {
                files.insert(file, state);
            } else {
                files.remove(&file);
            }
        }

        let state = Self::index_state(files, self.project.as_ref(), self.adapter.as_ref());
        Self::from_state(
            Arc::clone(&self.project),
            Arc::clone(&self.adapter),
            self.config.clone(),
            state,
        )
    }

    fn update_all(&self) -> Self {
        let state = Self::build_state(
            self.project.as_ref(),
            self.adapter.as_ref(),
            &self.config,
            None,
            None,
        );
        Self::from_state(
            Arc::clone(&self.project),
            Arc::clone(&self.adapter),
            self.config.clone(),
            state,
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
                .flat_map(|state| state.declarations.iter()),
        )
    }

    fn declarations<'a>(
        &'a self,
        file: &ProjectFile,
    ) -> Box<dyn Iterator<Item = &'a CodeUnit> + 'a> {
        match self.file_state(file) {
            Some(state) => Box::new(state.declarations.iter()),
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

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        self.adapter.extract_call_receiver(reference)
    }

    fn import_statements<'a>(&'a self, file: &ProjectFile) -> &'a [String] {
        self.file_state(file)
            .map(|state| state.import_statements.as_slice())
            .unwrap_or(&[])
    }

    fn enclosing_code_unit(&self, file: &ProjectFile, range: &Range) -> Option<CodeUnit> {
        if range.start_byte >= range.end_byte {
            return None;
        }

        self.declarations(file)
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
            .min_by_key(|(span, _)| *span)
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
            .flat_map(|(_, definitions)| definitions.iter().cloned().collect::<Vec<_>>())
            .collect()
    }

    fn metrics(&self) -> CodeBaseMetrics {
        CodeBaseMetrics::new(
            self.state.files.len(),
            self.state
                .files
                .values()
                .map(|state| state.declarations.len())
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
}

fn node_range(node: Node<'_>) -> Range {
    Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row + 1,
        end_line: node.end_position().row + 1,
    }
}

fn expanded_comment_start(source: &str, start_byte: usize) -> usize {
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

        if trimmed.trim().is_empty() {
            continue;
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
