use crate::analyzer::{
    AnalyzerConfig, CodeUnit, DeclarationInfo, ImportInfo, Language, Project, ProjectFile, Range,
};
use rayon::prelude::*;
use regex::RegexBuilder;
use std::collections::{BTreeMap, BTreeSet};
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
}

type BuildProgress = Arc<dyn Fn(usize, usize, &ProjectFile) + Send + Sync>;

#[derive(Debug, Clone)]
struct FileState {
    source: String,
    package_name: String,
    top_level_declarations: Vec<CodeUnit>,
    declarations: BTreeSet<CodeUnit>,
    import_statements: Vec<String>,
    imports: Vec<ImportInfo>,
    raw_supertypes: BTreeMap<CodeUnit, Vec<String>>,
    type_identifiers: BTreeSet<String>,
    signatures: BTreeMap<CodeUnit, Vec<String>>,
    ranges: BTreeMap<CodeUnit, Vec<Range>>,
    children: BTreeMap<CodeUnit, Vec<CodeUnit>>,
    type_aliases: BTreeSet<CodeUnit>,
    contains_tests: bool,
}

#[derive(Debug, Clone, Default)]
struct AnalyzerState {
    files: BTreeMap<ProjectFile, FileState>,
    definitions: BTreeMap<String, Vec<CodeUnit>>,
    children: BTreeMap<CodeUnit, Vec<CodeUnit>>,
    ranges: BTreeMap<CodeUnit, Vec<Range>>,
    raw_supertypes: BTreeMap<CodeUnit, Vec<String>>,
    signatures: BTreeMap<CodeUnit, Vec<String>>,
    #[allow(dead_code)]
    type_aliases: BTreeSet<CodeUnit>,
}

#[derive(Debug, Clone)]
pub struct ParsedFile {
    pub package_name: String,
    pub top_level_declarations: Vec<CodeUnit>,
    pub declarations: BTreeSet<CodeUnit>,
    pub import_statements: Vec<String>,
    pub imports: Vec<ImportInfo>,
    pub raw_supertypes: BTreeMap<CodeUnit, Vec<String>>,
    pub type_identifiers: BTreeSet<String>,
    pub signatures: BTreeMap<CodeUnit, Vec<String>>,
    pub type_aliases: BTreeSet<CodeUnit>,
    ranges: BTreeMap<CodeUnit, Vec<Range>>,
    children: BTreeMap<CodeUnit, Vec<CodeUnit>>,
}

impl ParsedFile {
    pub fn new(package_name: String) -> Self {
        Self {
            package_name,
            top_level_declarations: Vec::new(),
            declarations: BTreeSet::new(),
            import_statements: Vec::new(),
            imports: Vec::new(),
            raw_supertypes: BTreeMap::new(),
            type_identifiers: BTreeSet::new(),
            signatures: BTreeMap::new(),
            type_aliases: BTreeSet::new(),
            ranges: BTreeMap::new(),
            children: BTreeMap::new(),
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

    pub fn set_raw_supertypes(&mut self, code_unit: CodeUnit, raw_supertypes: Vec<String>) {
        self.raw_supertypes.insert(code_unit, raw_supertypes);
    }

    pub fn add_signature(&mut self, code_unit: CodeUnit, signature: String) {
        self.signatures
            .entry(code_unit)
            .or_default()
            .push(signature);
    }

    pub fn add_child(&mut self, parent: CodeUnit, child: CodeUnit) {
        self.children.entry(parent).or_default().push(child);
    }

    pub fn mark_type_alias(&mut self, code_unit: CodeUnit) {
        self.type_aliases.insert(code_unit);
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
    pub fn new(project: Arc<dyn Project>, adapter: A) -> Self {
        Self::new_with_config(project, adapter, AnalyzerConfig::default())
    }

    pub fn new_with_config(project: Arc<dyn Project>, adapter: A, config: AnalyzerConfig) -> Self {
        let adapter = Arc::new(adapter);
        let state = Arc::new(Self::build_state(
            project.as_ref(),
            adapter.as_ref(),
            &config,
            None,
            None,
        ));

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
        let source = file.read_to_string().ok()?;
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

        let mut analyzed = pool.install(|| {
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
        analyzed.sort_by(|(left, _), (right, _)| left.cmp(right));
        analyzed
    }

    fn build_state(
        project: &dyn Project,
        adapter: &A,
        config: &AnalyzerConfig,
        existing: Option<&AnalyzerState>,
        progress: Option<BuildProgress>,
    ) -> AnalyzerState {
        let mut files = existing
            .map(|state| state.files.clone())
            .unwrap_or_default();

        let analyzable_files: Vec<_> = project
            .analyzable_files(adapter.language())
            .unwrap_or_default()
            .into_iter()
            .collect();
        let analyzable_set: BTreeSet<_> = analyzable_files.iter().cloned().collect();

        files.retain(|file, _| analyzable_set.contains(file));

        for (file, state) in Self::analyze_files(adapter, config, analyzable_files, progress) {
            if let Some(state) = state {
                files.insert(file, state);
            } else {
                files.remove(&file);
            }
        }

        Self::index_state(files, project, adapter)
    }

    fn index_state(
        files: BTreeMap<ProjectFile, FileState>,
        project: &dyn Project,
        adapter: &A,
    ) -> AnalyzerState {
        let mut definitions = BTreeMap::<String, Vec<CodeUnit>>::new();
        let mut children = BTreeMap::<CodeUnit, Vec<CodeUnit>>::new();
        let mut ranges = BTreeMap::<CodeUnit, Vec<Range>>::new();
        let mut raw_supertypes = BTreeMap::<CodeUnit, Vec<String>>::new();
        let mut signatures = BTreeMap::<CodeUnit, Vec<String>>::new();
        let mut type_aliases = BTreeSet::<CodeUnit>::new();

        for state in files.values() {
            for declaration in &state.declarations {
                definitions
                    .entry(adapter.normalize_full_name(&declaration.fq_name()))
                    .or_default()
                    .push(declaration.clone());
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

        for descendants in children.values_mut() {
            descendants.sort();
            descendants.dedup();
        }

        for matches in definitions.values_mut() {
            matches.sort();
            matches.dedup();
        }

        let _ = project;

        AnalyzerState {
            files,
            definitions,
            children,
            ranges,
            raw_supertypes,
            signatures,
            type_aliases,
        }
    }

    fn file_state(&self, file: &ProjectFile) -> Option<&FileState> {
        self.state.files.get(file)
    }

    pub(crate) fn package_name_of(&self, file: &ProjectFile) -> Option<&str> {
        self.file_state(file)
            .map(|state| state.package_name.as_str())
    }

    pub(crate) fn import_info_of(&self, file: &ProjectFile) -> Vec<ImportInfo> {
        self.file_state(file)
            .map(|state| state.imports.clone())
            .unwrap_or_default()
    }

    pub(crate) fn raw_supertypes_of(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.state
            .raw_supertypes
            .get(code_unit)
            .cloned()
            .or_else(|| {
                self.file_state(code_unit.source())
                    .and_then(|state| state.raw_supertypes.get(code_unit).cloned())
            })
            .unwrap_or_default()
    }

    pub(crate) fn type_identifiers_of(&self, file: &ProjectFile) -> BTreeSet<String> {
        self.file_state(file)
            .map(|state| state.type_identifiers.clone())
            .unwrap_or_default()
    }

    pub(crate) fn all_files(&self) -> BTreeSet<ProjectFile> {
        self.state.files.keys().cloned().collect()
    }

    #[allow(dead_code)]
    pub(crate) fn is_type_alias(&self, code_unit: &CodeUnit) -> bool {
        self.state.type_aliases.contains(code_unit)
    }

    fn signatures_of(&self, code_unit: &CodeUnit) -> Vec<String> {
        self.state
            .signatures
            .get(code_unit)
            .cloned()
            .or_else(|| {
                self.file_state(code_unit.source())
                    .and_then(|state| state.signatures.get(code_unit).cloned())
            })
            .unwrap_or_default()
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

        let all_children = crate::analyzer::IAnalyzer::get_direct_children(self, code_unit);
        let field_children: Vec<_> = all_children
            .iter()
            .filter(|child| child.is_field())
            .cloned()
            .collect();
        let children = if header_only {
            field_children.clone()
        } else {
            all_children.clone()
        };

        if !children.is_empty() || code_unit.is_class() {
            let child_indent = format!("{indent}  ");
            for child in children {
                self.render_skeleton_recursive(&child, &child_indent, header_only, out);
            }
            if header_only && all_children.len() > field_children.len() {
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

impl<A> crate::analyzer::IAnalyzer for TreeSitterAnalyzer<A>
where
    A: LanguageAdapter,
{
    fn get_top_level_declarations(&self, file: &ProjectFile) -> Vec<CodeUnit> {
        self.file_state(file)
            .map(|state| state.top_level_declarations.clone())
            .unwrap_or_default()
    }

    fn get_analyzed_files(&self) -> BTreeSet<ProjectFile> {
        self.state.files.keys().cloned().collect()
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

    fn get_all_declarations(&self) -> Vec<CodeUnit> {
        self.state
            .files
            .values()
            .flat_map(|state| state.declarations.iter().cloned())
            .collect()
    }

    fn get_declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
        self.file_state(file)
            .map(|state| state.declarations.clone())
            .unwrap_or_default()
    }

    fn get_definitions(&self, fq_name: &str) -> Vec<CodeUnit> {
        let matches = self
            .state
            .definitions
            .get(&self.adapter.normalize_full_name(fq_name))
            .cloned()
            .unwrap_or_default();

        let mut result = Vec::new();
        let mut saw_module = false;
        for code_unit in matches {
            if code_unit.is_module() {
                if saw_module {
                    continue;
                }
                saw_module = true;
            }
            result.push(code_unit);
        }
        result
    }

    fn get_direct_children(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        let mut children = if code_unit.is_module() {
            let target_name = self.adapter.normalize_full_name(&code_unit.fq_name());
            self.state
                .children
                .iter()
                .filter(|(parent, _)| {
                    parent.is_module()
                        && self.adapter.normalize_full_name(&parent.fq_name()) == target_name
                })
                .flat_map(|(_, descendants)| descendants.iter().cloned())
                .collect::<Vec<_>>()
        } else {
            self.state
                .children
                .get(code_unit)
                .cloned()
                .unwrap_or_default()
        };

        children.sort();
        children.dedup();
        children.sort_by_key(|child| {
            self.ranges_of(child)
                .into_iter()
                .map(|range| range.start_byte)
                .min()
                .unwrap_or(usize::MAX)
        });
        children
    }

    fn extract_call_receiver(&self, reference: &str) -> Option<String> {
        self.adapter.extract_call_receiver(reference)
    }

    fn import_statements_of(&self, file: &ProjectFile) -> Vec<String> {
        self.file_state(file)
            .map(|state| state.import_statements.clone())
            .unwrap_or_default()
    }

    fn enclosing_code_unit(&self, file: &ProjectFile, range: &Range) -> Option<CodeUnit> {
        if range.start_byte >= range.end_byte {
            return None;
        }

        self.get_declarations(file)
            .into_iter()
            .filter_map(|code_unit| {
                let best_range = self
                    .ranges_of(&code_unit)
                    .into_iter()
                    .find(|candidate| candidate.contains(range))?;
                Some((best_range.end_byte - best_range.start_byte, code_unit))
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
        self.get_declarations(file)
            .into_iter()
            .filter_map(|code_unit| {
                let best_range = self.ranges_of(&code_unit).into_iter().find(|candidate| {
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

    fn ranges_of(&self, code_unit: &CodeUnit) -> Vec<Range> {
        self.state
            .ranges
            .get(code_unit)
            .cloned()
            .unwrap_or_default()
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
            for candidate in self.get_definitions(&code_unit.fq_name()) {
                if candidate.source() == code_unit.source() {
                    grouped.extend(self.ranges_of(&candidate));
                }
            }
            grouped
        } else {
            self.ranges_of(code_unit)
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

        self.get_all_declarations()
            .into_iter()
            .filter(|code_unit| !self.adapter.is_anonymous_structure(&code_unit.fq_name()))
            .filter(|code_unit| compiled.is_match(&code_unit.fq_name()))
            .collect()
    }

    fn contains_tests(&self, file: &ProjectFile) -> bool {
        self.file_state(file)
            .map(|state| state.contains_tests)
            .unwrap_or(false)
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
    let mut line_starts = vec![0usize];
    for (idx, ch) in source.char_indices() {
        if ch == '\n' && idx + 1 < source.len() {
            line_starts.push(idx + 1);
        }
    }

    let line_index = match line_starts.binary_search(&start_byte) {
        Ok(index) => index,
        Err(index) => index.saturating_sub(1),
    };

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
}

fn first_comment_offset(line: &str) -> Option<usize> {
    ["/**", "/*", "//"]
        .into_iter()
        .filter_map(|marker| line.find(marker))
        .min()
}
