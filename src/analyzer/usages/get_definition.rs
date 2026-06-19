use crate::analyzer::common::language_for_file;
use crate::analyzer::usages::cpp_graph::{
    CppTargetKind, CppVisibilityIndex, cpp_call_arity, cpp_first_type_child,
    cpp_is_declaration_name, cpp_is_declarator_node, cpp_name_for, cpp_signature_arity,
    cpp_split_top_level_commas, extract_variable_name, normalize_cpp_type_text,
};
use crate::analyzer::usages::csharp_graph::{
    csharp_argument_count, csharp_first_type_child, csharp_is_declaration_name,
    csharp_is_type_reference_node, csharp_member_declared_type_fq_name, csharp_node_text,
    csharp_reference_type_text, csharp_signature_arity,
    member_access_name as csharp_member_access_name,
    member_access_receiver as csharp_member_access_receiver, seed_csharp_bindings_before,
};
use crate::analyzer::usages::go_graph::{
    GoProjectGraph, build_workspace_go_graph, default_go_import_local_name, extract_go_import_path,
    preparse_go_files, resolve_go_reference,
};
use crate::analyzer::usages::inverted_edges::{ClassRangeIndex, first_precise};
use crate::analyzer::usages::js_ts_graph::{cached_jsts_index, compute_jsts_import_binder};
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::usages::model::{ImportBinder, ImportKind};
use crate::analyzer::usages::php_graph::{
    FileContext, php_node_text, php_qualified_candidate_text, resolve_php_constant,
    resolve_php_function, resolve_php_type,
};
use crate::analyzer::usages::python_graph::{
    collect_assigned_identifiers, collect_scope_facts, enclosing_scope_facts,
    is_declaration_identifier as python_is_declaration_identifier, python_slice,
    resolve_receiver_type as resolve_python_receiver_type,
};
use crate::analyzer::usages::scala_graph::{
    ScalaNameResolver, ScalaProjectTypes, package_name_of as scala_package_name_of,
    scala_import_path, scala_node_text,
};
use crate::analyzer::{
    AliasResolver, CSharpAnalyzer, CodeUnit, CppAnalyzer, DefinitionLookupIndex, GoAnalyzer,
    IAnalyzer, ImportAnalysisProvider, JavaAnalyzer, Language, PhpAnalyzer, ProjectFile,
    PythonAnalyzer, Range, RustAnalyzer, ScalaAnalyzer, cpp_include_paths, cpp_node_text,
    parse_php_use_aliases_from_source, resolve_analyzer, resolve_include_targets,
};
use crate::hash::{HashMap, HashSet};
use crate::path_utils::rel_path_string;
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tree_sitter::{Node, Parser, Tree};

#[derive(Debug, Clone)]
pub(crate) struct DefinitionLookupRequest {
    pub(crate) file: ProjectFile,
    pub(crate) line: Option<usize>,
    pub(crate) column: Option<usize>,
    pub(crate) start_byte: Option<usize>,
    pub(crate) end_byte: Option<usize>,
}

#[derive(Debug, Clone)]
pub(crate) struct DefinitionLookupOutcome {
    pub(crate) status: DefinitionLookupStatus,
    pub(crate) reference: Option<ResolvedReferenceSite>,
    pub(crate) definitions: Vec<CodeUnit>,
    pub(crate) diagnostics: Vec<DefinitionLookupDiagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DefinitionLookupStatus {
    Resolved,
    NoDefinition,
    UnresolvableImportBoundary,
    Ambiguous,
    UnsupportedLanguage,
    InvalidLocation,
    NotFound,
}

impl DefinitionLookupStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Resolved => "resolved",
            Self::NoDefinition => "no_definition",
            Self::UnresolvableImportBoundary => "unresolvable_import_boundary",
            Self::Ambiguous => "ambiguous",
            Self::UnsupportedLanguage => "unsupported_language",
            Self::InvalidLocation => "invalid_location",
            Self::NotFound => "not_found",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedReferenceSite {
    pub(crate) path: String,
    pub(crate) text: String,
    pub(crate) range: Range,
    pub(crate) focus_start_byte: usize,
    pub(crate) focus_end_byte: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct DefinitionLookupDiagnostic {
    pub(crate) kind: String,
    pub(crate) message: String,
}

pub(crate) fn resolve_definition_batch(
    analyzer: &dyn IAnalyzer,
    requests: Vec<DefinitionLookupRequest>,
) -> Vec<DefinitionLookupOutcome> {
    let mut context = DefinitionBatchContext::new(analyzer);
    requests
        .into_iter()
        .map(|request| resolve_one(analyzer, &mut context, request))
        .collect()
}

struct DefinitionBatchContext<'a> {
    support: &'a DefinitionLookupIndex,
    sources: HashMap<ProjectFile, Result<Arc<String>, String>>,
    trees: HashMap<(ProjectFile, Language), Option<Tree>>,
    cpp_visibility: HashMap<ProjectFile, Arc<CppVisibilityIndex>>,
    scala_project_types: Option<Arc<ScalaProjectTypes>>,
    go_graph: Option<Option<Arc<GoProjectGraph>>>,
}

impl<'a> DefinitionBatchContext<'a> {
    fn new(analyzer: &'a dyn IAnalyzer) -> Self {
        Self {
            support: analyzer.definition_lookup_index(),
            sources: HashMap::default(),
            trees: HashMap::default(),
            cpp_visibility: HashMap::default(),
            scala_project_types: None,
            go_graph: None,
        }
    }

    fn source(&mut self, file: &ProjectFile) -> Result<Arc<String>, String> {
        self.sources
            .entry(file.clone())
            .or_insert_with(|| {
                file.read_to_string()
                    .map(Arc::new)
                    .map_err(|err| format!("failed to read `{}`: {err}", rel_path_string(file)))
            })
            .clone()
    }

    fn tree(&mut self, file: &ProjectFile, language: Language, source: &str) -> Option<Tree> {
        self.trees
            .entry((file.clone(), language))
            .or_insert_with(|| parse_tree_for_language(file, language, source))
            .clone()
    }

    fn cpp_visibility(
        &mut self,
        cpp: &crate::analyzer::CppAnalyzer,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
    ) -> Arc<CppVisibilityIndex> {
        self.cpp_visibility
            .entry(file.clone())
            .or_insert_with(|| {
                let mut roots = HashSet::default();
                roots.insert(file.clone());
                Arc::new(CppVisibilityIndex::build(cpp, analyzer, &roots))
            })
            .clone()
    }

    fn scala_project_types(&mut self, scala: &ScalaAnalyzer) -> Arc<ScalaProjectTypes> {
        self.scala_project_types
            .get_or_insert_with(|| Arc::new(ScalaProjectTypes::build(scala)))
            .clone()
    }

    fn go_graph(
        &mut self,
        go: &crate::analyzer::GoAnalyzer,
        analyzer: &dyn IAnalyzer,
    ) -> Option<Arc<GoProjectGraph>> {
        if self.go_graph.is_none() {
            let graph = analyzer
                .project()
                .analyzable_files(Language::Go)
                .ok()
                .and_then(|files| {
                    let files: Vec<ProjectFile> = files.into_iter().collect();
                    if files.is_empty() {
                        return None;
                    }
                    let cache = preparse_go_files(&files);
                    build_workspace_go_graph(go, &files, Some(&cache)).map(Arc::new)
                });
            self.go_graph = Some(graph);
        }
        self.go_graph.as_ref().and_then(Clone::clone)
    }
}

fn resolve_one(
    analyzer: &dyn IAnalyzer,
    context: &mut DefinitionBatchContext<'_>,
    request: DefinitionLookupRequest,
) -> DefinitionLookupOutcome {
    let language = language_for_file(&request.file);
    if language == Language::None {
        return diagnostic_outcome(
            DefinitionLookupStatus::UnsupportedLanguage,
            "unsupported_language",
            format!("{language:?} get_definition is not implemented yet"),
        );
    }

    let source = match context.source(&request.file) {
        Ok(source) => source,
        Err(message) => {
            return diagnostic_outcome(
                DefinitionLookupStatus::NotFound,
                "file_read_failed",
                message,
            );
        }
    };

    let site = match resolve_reference_site(&request, &source) {
        Ok(site) => site,
        Err(message) => {
            return diagnostic_outcome(
                DefinitionLookupStatus::InvalidLocation,
                "invalid_location",
                message,
            );
        }
    };
    let site = if matches!(language, Language::JavaScript | Language::TypeScript) {
        jsts_site_for_focus(site)
    } else {
        site
    };

    let tree = context.tree(&request.file, language, &source);
    let resolved = match language {
        Language::Rust => resolve_rust(
            analyzer,
            context.support,
            &request.file,
            &source,
            &site.text,
        ),
        Language::JavaScript | Language::TypeScript => resolve_js_ts(
            analyzer,
            context.support,
            &request.file,
            language,
            &source,
            tree.as_ref(),
            &site,
        ),
        Language::Go => {
            let go = resolve_analyzer::<GoAnalyzer>(analyzer);
            let go_graph = go.and_then(|go| context.go_graph(go, analyzer));
            resolve_go(
                analyzer,
                context.support,
                &request.file,
                &source,
                &site,
                go_graph.as_deref(),
            )
        }
        Language::Java => resolve_java(
            analyzer,
            context.support,
            &request.file,
            &source,
            tree.as_ref(),
            &site,
        ),
        Language::Php => resolve_php(
            analyzer,
            context.support,
            &request.file,
            &source,
            tree.as_ref(),
            &site,
        ),
        Language::Python => resolve_python(
            analyzer,
            context.support,
            &request.file,
            &source,
            tree.as_ref(),
            &site,
        ),
        Language::CSharp => resolve_csharp(
            analyzer,
            context.support,
            &request.file,
            &source,
            tree.as_ref(),
            &site,
        ),
        Language::Cpp => resolve_cpp(
            analyzer,
            context,
            &request.file,
            &source,
            tree.as_ref(),
            &site,
        ),
        Language::Scala => resolve_scala(
            analyzer,
            context,
            &request.file,
            &source,
            tree.as_ref(),
            &site,
        ),
        Language::None => unreachable!("unsupported language handled before source extraction"),
    };

    finish_lookup_outcome(resolved, site)
}

fn finish_lookup_outcome(
    mut outcome: DefinitionLookupOutcome,
    site: ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    outcome.reference = Some(site);
    outcome
}

fn resolve_reference_site(
    request: &DefinitionLookupRequest,
    source: &str,
) -> Result<ResolvedReferenceSite, String> {
    let line_starts = compute_line_starts(source);
    let (selection_start, selection_end) = match (
        request.start_byte,
        request.end_byte,
        request.line,
        request.column,
    ) {
        (Some(start), Some(end), _, _) => {
            if start >= end || end > source.len() {
                return Err(format!(
                    "invalid byte range [{start}, {end}) for {} byte file",
                    source.len()
                ));
            }
            if !source.is_char_boundary(start) || !source.is_char_boundary(end) {
                return Err(format!(
                    "byte range [{start}, {end}) does not align to UTF-8 character boundaries"
                ));
            }
            let token = token_bounds_at(source, start)
                .ok_or_else(|| format!("no reference token at byte {start}"))?;
            if end > token.1 {
                return Err(
                    "byte range must identify a single reference token; use start_byte inside the token for qualified expressions"
                        .to_string(),
                );
            }
            token
        }
        (Some(start), None, _, _) => {
            if start >= source.len() {
                return Err(format!(
                    "start_byte {start} is outside {} byte file",
                    source.len()
                ));
            }
            if !source.is_char_boundary(start) {
                return Err(format!(
                    "start_byte {start} does not align to a UTF-8 character boundary"
                ));
            }
            token_bounds_at(source, start)
                .ok_or_else(|| format!("no reference token at byte {start}"))?
        }
        (_, _, Some(line), column) => {
            if line == 0 || line > line_starts.len() {
                return Err(format!(
                    "line {line} is outside 1..={} for this file",
                    line_starts.len()
                ));
            }
            let line_start = line_starts[line - 1];
            let line_end = line_starts.get(line).copied().unwrap_or(source.len());
            let column = column.unwrap_or(1);
            if column == 0 {
                return Err("column must be 1-based".to_string());
            }
            let point =
                byte_offset_for_character_column(source, line_start, line_end, line, column)?;
            token_bounds_at(source, point.min(source.len().saturating_sub(1)))
                .ok_or_else(|| format!("no reference token at line {line}, column {column}"))?
        }
        _ => return Err("provide either start_byte or line/column".to_string()),
    };

    let (start, end) = expand_reference_expression(source, selection_start, selection_end);
    if start >= end {
        return Err("reference selection is empty".to_string());
    }
    if !source.is_char_boundary(start) || !source.is_char_boundary(end) {
        return Err("reference selection does not align to UTF-8 character boundaries".to_string());
    }
    let text = source[start..end].trim().to_string();
    if text.is_empty() {
        return Err("reference selection is blank".to_string());
    }
    let start_line = find_line_index_for_offset(&line_starts, start) + 1;
    let end_line = find_line_index_for_offset(&line_starts, end.saturating_sub(1)) + 1;
    Ok(ResolvedReferenceSite {
        path: rel_path_string(&request.file),
        text,
        range: Range {
            start_byte: start,
            end_byte: end,
            start_line,
            end_line,
        },
        focus_start_byte: selection_start,
        focus_end_byte: selection_end,
    })
}

fn byte_offset_for_character_column(
    source: &str,
    line_start: usize,
    line_end: usize,
    line_number: usize,
    column: usize,
) -> Result<usize, String> {
    let line = source
        .get(line_start..line_end)
        .ok_or_else(|| format!("line {line_number} is outside valid UTF-8 boundaries"))?;
    let character_offset = column - 1;
    if character_offset == 0 {
        return Ok(line_start);
    }
    if let Some((byte_offset, _)) = line.char_indices().nth(character_offset) {
        return Ok(line_start + byte_offset);
    }
    if character_offset == line.chars().count() {
        return Ok(line_end);
    }
    Err(format!("column {column} is outside line {line_number}"))
}

fn token_bounds_at(source: &str, byte: usize) -> Option<(usize, usize)> {
    if source.is_empty() {
        return None;
    }
    let bytes = source.as_bytes();
    let mut idx = byte.min(bytes.len().saturating_sub(1));
    if !is_ident_byte(bytes[idx]) && idx > 0 && is_ident_byte(bytes[idx - 1]) {
        idx -= 1;
    }
    if !is_ident_byte(bytes[idx]) {
        return None;
    }
    let mut start = idx;
    while start > 0 && is_ident_byte(bytes[start - 1]) {
        start -= 1;
    }
    let mut end = idx + 1;
    while end < bytes.len() && is_ident_byte(bytes[end]) {
        end += 1;
    }
    Some((start, end))
}

fn expand_reference_expression(source: &str, start: usize, end: usize) -> (usize, usize) {
    let bytes = source.as_bytes();
    let mut left = start;
    let mut right = end;
    loop {
        if left >= 2 && &source[left - 2..left] == "::" {
            left -= 2;
            while left > 0 && is_ident_byte(bytes[left - 1]) {
                left -= 1;
            }
            continue;
        }
        if left >= 1 && bytes[left - 1] == b'.' {
            left -= 1;
            while left > 0 && is_ident_byte(bytes[left - 1]) {
                left -= 1;
            }
            continue;
        }
        break;
    }
    loop {
        if right + 2 <= source.len() && &source[right..right + 2] == "::" {
            right += 2;
            while right < bytes.len() && is_ident_byte(bytes[right]) {
                right += 1;
            }
            continue;
        }
        if right < bytes.len() && bytes[right] == b'.' {
            right += 1;
            while right < bytes.len() && is_ident_byte(bytes[right]) {
                right += 1;
            }
            continue;
        }
        break;
    }
    (left, right)
}

fn is_ident_byte(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

fn resolve_rust(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    reference: &str,
) -> DefinitionLookupOutcome {
    let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer) else {
        return no_definition("rust_analyzer_unavailable", "Rust analyzer is unavailable");
    };
    let refs = rust.reference_context_of(file);
    let (candidates, scoped_lookup_failed) = if let Some((path, name)) = reference.rsplit_once("::")
    {
        let resolved = refs
            .resolve_scoped(path, name)
            .map(|fqn| support.fqn(&fqn))
            .unwrap_or_default();
        (resolved, true)
    } else {
        let mut resolved = refs
            .resolve_bare(reference)
            .map(|fqn| support.fqn(fqn))
            .unwrap_or_default();
        if resolved.is_empty() {
            let imported = rust_import_candidates(analyzer, rust, support, file, source, reference);
            resolved = if imported.is_empty() {
                support.file_identifier(file, reference)
            } else {
                imported
            };
        }
        (resolved, false)
    };
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }
    if rust_reference_looks_external(reference) {
        return boundary(format!(
            "`{reference}` appears to cross a Rust crate/module boundary not indexed in this workspace"
        ));
    }
    if scoped_lookup_failed {
        return no_definition(
            "no_indexed_definition",
            format!("`{reference}` did not resolve through its Rust module path"),
        );
    }
    no_definition(
        "no_indexed_definition",
        format!("`{reference}` did not resolve to an indexed Rust definition"),
    )
}

fn rust_import_candidates(
    analyzer: &dyn IAnalyzer,
    rust: &crate::analyzer::RustAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    reference: &str,
) -> Vec<CodeUnit> {
    let statement_candidates =
        rust_import_statement_candidates(analyzer, rust, support, file, source, reference);
    if !statement_candidates.is_empty() {
        return statement_candidates;
    }

    let binder = rust.import_binder_of(file);
    let Some(binding) = binder.bindings.get(reference) else {
        return Vec::new();
    };
    match binding.kind {
        ImportKind::Named => {
            let imported = binding.imported_name.as_deref().unwrap_or(reference);
            let package = rust.resolve_module_package(file, &binding.module_specifier);
            let mut candidates = package
                .as_ref()
                .map(|package| support.fqn(&format!("{package}.{imported}")))
                .unwrap_or_default();
            if candidates.is_empty() {
                let files = rust.resolve_module_files(file, &binding.module_specifier);
                candidates = support.file_identifier_in_files(&files, imported);
            }
            candidates
        }
        ImportKind::Namespace => {
            let Some((module_specifier, imported)) = binding.module_specifier.rsplit_once("::")
            else {
                return Vec::new();
            };
            let files = rust.resolve_module_files(file, module_specifier);
            support.file_identifier_in_files(&files, imported)
        }
        ImportKind::Default | ImportKind::CommonJsRequire | ImportKind::Glob => Vec::new(),
    }
}

fn rust_import_statement_candidates(
    analyzer: &dyn IAnalyzer,
    rust: &crate::analyzer::RustAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    reference: &str,
) -> Vec<CodeUnit> {
    let import_statements = analyzer.import_statements(file);
    let flattened_imports: Vec<String> = import_statements
        .iter()
        .map(String::as_str)
        .chain(
            rust_use_statements_from_source(source)
                .iter()
                .map(String::as_str),
        )
        .flat_map(crate::analyzer::rust::flatten_rust_use)
        .collect();
    for raw in flattened_imports {
        let mut path = raw.trim();
        path = path.strip_prefix("pub ").unwrap_or(path).trim();
        let Some(rest) = path.strip_prefix("use ") else {
            continue;
        };
        path = rest.trim_end_matches(';').trim();
        if path.contains('{') || path.ends_with("::*") {
            continue;
        }
        let (path_without_alias, local_name) = match path.rsplit_once(" as ") {
            Some((target, alias)) => (target.trim(), alias.trim()),
            None => {
                let local = path.rsplit("::").next().unwrap_or(path);
                (path, local)
            }
        };
        if local_name != reference {
            continue;
        }
        let Some((module_specifier, imported_name)) = path_without_alias.rsplit_once("::") else {
            continue;
        };
        let mut files = rust.resolve_module_files(file, module_specifier);
        files.extend(rust_module_files_from_path(file, module_specifier));
        let candidates = support.file_identifier_in_files(&files, imported_name);
        if !candidates.is_empty() {
            return candidates;
        }
    }
    Vec::new()
}

fn rust_use_statements_from_source(source: &str) -> Vec<String> {
    let mut statements = Vec::new();
    let mut current = String::new();
    let mut collecting = false;
    for line in source.lines() {
        let trimmed = line.trim();
        if !collecting && !trimmed.starts_with("use ") && !trimmed.starts_with("pub use ") {
            continue;
        }
        if collecting {
            current.push(' ');
        }
        current.push_str(trimmed);
        collecting = true;
        if trimmed.ends_with(';') {
            statements.push(std::mem::take(&mut current));
            collecting = false;
        }
    }
    statements
}

fn rust_module_files_from_path(file: &ProjectFile, module_specifier: &str) -> Vec<ProjectFile> {
    let Some(relative_module) = rust_relative_module_path(file, module_specifier) else {
        return Vec::new();
    };
    let mut files = Vec::new();
    for rel_path in [
        relative_module.with_extension("rs"),
        relative_module.join("mod.rs"),
        PathBuf::from("src")
            .join(&relative_module)
            .with_extension("rs"),
        PathBuf::from("src").join(&relative_module).join("mod.rs"),
    ] {
        let candidate = ProjectFile::new(file.root().to_path_buf(), rel_path);
        if candidate.exists() {
            files.push(candidate);
        }
    }
    files
}

fn rust_relative_module_path(file: &ProjectFile, module_specifier: &str) -> Option<PathBuf> {
    let module = module_specifier
        .strip_prefix("crate::")
        .or_else(|| module_specifier.strip_prefix("self::"))
        .map(PathBuf::from)
        .or_else(|| {
            module_specifier
                .strip_prefix("super::")
                .map(|rest| file.parent().parent().unwrap_or(Path::new("")).join(rest))
        })
        .or_else(|| {
            let (crate_name, rest) = module_specifier.split_once("::")?;
            (Some(crate_name) == rust_current_crate_name(file).as_deref()).then(|| rest.into())
        })?;
    Some(module.to_string_lossy().replace("::", "/").into())
}

fn rust_current_crate_name(file: &ProjectFile) -> Option<String> {
    let manifest = file.root().join("Cargo.toml");
    let source = std::fs::read_to_string(manifest).ok()?;
    source.lines().find_map(|line| {
        let trimmed = line.trim();
        let value = trimmed.strip_prefix("name")?.trim_start();
        let value = value.strip_prefix('=')?.trim();
        value
            .trim_matches('"')
            .split('"')
            .next()
            .filter(|name| !name.is_empty())
            .map(|name| name.replace('-', "_"))
    })
}

fn rust_reference_looks_external(reference: &str) -> bool {
    reference
        .split("::")
        .next()
        .is_some_and(|root| !matches!(root, "crate" | "self" | "super") && root != reference)
}

fn parse_tree_for_language(file: &ProjectFile, language: Language, source: &str) -> Option<Tree> {
    match language {
        Language::JavaScript | Language::TypeScript => parse_js_ts_tree(file, source, language),
        Language::Cpp => parse_cpp_tree(source),
        Language::Scala => parse_scala_tree(source),
        Language::Java => parse_java_tree(source),
        Language::Php => parse_php_tree(source),
        Language::CSharp => parse_csharp_tree(source),
        Language::Python => parse_python_tree(source),
        Language::Rust | Language::Go | Language::None => None,
    }
}

fn resolve_js_ts(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    language: Language,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    let Some(tree) = tree else {
        return no_definition("jsts_parse_failed", "JS/TS source could not be parsed");
    };
    let reference = site.text.as_str();
    let value_position = jsts_reference_is_value_position(tree, site);
    let imports = compute_jsts_import_binder(source, tree);
    let aliases = AliasResolver::new(analyzer.project().root().to_path_buf());

    if let Some((qualifier, name)) = reference.split_once('.') {
        if let Some(binding) = imports.bindings.get(qualifier)
            && matches!(
                binding.kind,
                ImportKind::Namespace | ImportKind::CommonJsRequire
            )
        {
            return resolve_js_ts_module_binding(
                file,
                language,
                &binding.module_specifier,
                name,
                analyzer,
                support,
                Some(&aliases),
                value_position,
            );
        }
        let receiver_candidates = if let Some(binding) = imports.bindings.get(qualifier)
            && matches!(binding.kind, ImportKind::Named | ImportKind::Default)
        {
            let exported_name = match binding.kind {
                ImportKind::Named => binding.imported_name.as_deref().unwrap_or(qualifier),
                ImportKind::Default => "default",
                _ => qualifier,
            };
            resolve_js_ts_module_binding_candidates(
                analyzer,
                support,
                language,
                file,
                &binding.module_specifier,
                exported_name,
                Some(&aliases),
                value_position,
            )
        } else {
            let mut same_file = support.file_identifier(file, qualifier);
            if value_position {
                same_file = jsts_value_space_candidates(analyzer, same_file);
            } else {
                same_file = jsts_type_space_candidates(analyzer, same_file);
            }
            same_file
        };
        let member_candidates = if language == Language::TypeScript {
            ts_member_candidates(analyzer, support, receiver_candidates, name, value_position)
        } else {
            jsts_member_candidates(analyzer, support, receiver_candidates, name, value_position)
        };
        if !member_candidates.is_empty() {
            return candidates_outcome(member_candidates);
        }
        if language == Language::TypeScript {
            let inferred_receivers = ts_local_receiver_owner_candidates(
                analyzer, support, file, source, tree, site, &imports, &aliases, qualifier,
            );
            let inferred_member_candidates =
                jsts_member_candidates(analyzer, support, inferred_receivers, name, value_position);
            if !inferred_member_candidates.is_empty() {
                return candidates_outcome(inferred_member_candidates);
            }
            if let Some(receiver_type) = ts_global_object_receiver_type(qualifier) {
                let global_receivers = support
                    .fqn(receiver_type)
                    .into_iter()
                    .filter(|unit| jsts_unit_is_type_only(analyzer, unit))
                    .collect();
                let global_member_candidates =
                    ts_member_candidates(analyzer, support, global_receivers, name, value_position);
                if !global_member_candidates.is_empty() {
                    return candidates_outcome(global_member_candidates);
                }
            }
        }
        return no_definition(
            "no_indexed_definition",
            format!("`{reference}` did not resolve to an indexed JS/TS definition"),
        );
    }

    if let Some(binding) = imports.bindings.get(reference) {
        let exported_name = match binding.kind {
            ImportKind::Named => binding.imported_name.as_deref().unwrap_or(reference),
            ImportKind::Default => "default",
            ImportKind::Namespace | ImportKind::CommonJsRequire | ImportKind::Glob => reference,
        };
        if matches!(binding.kind, ImportKind::Named | ImportKind::Default) {
            return resolve_js_ts_module_binding(
                file,
                language,
                &binding.module_specifier,
                exported_name,
                analyzer,
                support,
                Some(&aliases),
                value_position,
            );
        }
    }

    let mut same_file = support.file_identifier(file, reference);
    if value_position {
        same_file = jsts_value_space_candidates(analyzer, same_file);
    } else {
        same_file = jsts_type_space_candidates(analyzer, same_file);
    }
    if !same_file.is_empty() {
        return candidates_outcome(same_file);
    }

    no_definition(
        "no_indexed_definition",
        format!("`{reference}` did not resolve to an indexed JS/TS definition"),
    )
}

fn ts_global_object_receiver_type(receiver: &str) -> Option<&'static str> {
    match receiver {
        "window" => Some("Window"),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn resolve_js_ts_module_binding(
    file: &ProjectFile,
    language: Language,
    module: &str,
    exported_name: &str,
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    aliases: Option<&AliasResolver>,
    value_position: bool,
) -> DefinitionLookupOutcome {
    let files = crate::analyzer::resolve_js_ts_module_specifier(file, module, language, aliases);
    if files.is_empty() {
        if is_bare_js_ts_specifier(module) {
            return boundary(format!(
                "`{module}` is a package import outside this partial workspace analysis"
            ));
        }
        return boundary(format!(
            "`{module}` could not be resolved to a workspace JS/TS file"
        ));
    }

    let candidates = resolve_js_ts_module_binding_candidates(
        analyzer,
        support,
        language,
        file,
        module,
        exported_name,
        aliases,
        value_position,
    );
    if candidates.is_empty() {
        return no_definition(
            "no_indexed_definition",
            format!("`{exported_name}` is not indexed in `{module}`"),
        );
    }
    candidates_outcome(candidates)
}

#[allow(clippy::too_many_arguments)]
fn resolve_js_ts_module_binding_candidates(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    language: Language,
    file: &ProjectFile,
    module: &str,
    exported_name: &str,
    aliases: Option<&AliasResolver>,
    value_position: bool,
) -> Vec<CodeUnit> {
    let files = crate::analyzer::resolve_js_ts_module_specifier(file, module, language, aliases);
    if files.is_empty() {
        return Vec::new();
    }

    let mut candidates = jsts_module_export_candidates(
        analyzer,
        support,
        language,
        &files,
        exported_name,
        value_position,
    );
    if value_position {
        candidates = jsts_value_space_candidates(analyzer, candidates);
    } else {
        candidates = jsts_type_space_candidates(analyzer, candidates);
    }
    if candidates.is_empty() && exported_name == "default" {
        for file in &files {
            candidates.extend(
                analyzer
                    .declarations(file)
                    .filter(|unit| unit.identifier() == "default")
                    .cloned(),
            );
        }
        sort_units(&mut candidates);
        candidates.dedup();
        if value_position {
            candidates = jsts_value_space_candidates(analyzer, candidates);
        } else {
            candidates = jsts_type_space_candidates(analyzer, candidates);
        }
    }
    candidates
}

fn jsts_module_export_candidates(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    language: Language,
    files: &[ProjectFile],
    exported_name: &str,
    value_position: bool,
) -> Vec<CodeUnit> {
    let Some(index) = cached_jsts_index(analyzer, language) else {
        return Vec::new();
    };

    let bindings = index.local_bindings_for_exported_name(files, exported_name);
    let mut candidates = Vec::new();
    for (file, local_name) in bindings {
        let file_candidates = support.file_identifier_in_files(&[file], &local_name);
        candidates.extend(file_candidates);
    }

    if value_position {
        jsts_value_space_candidates(analyzer, candidates)
    } else {
        jsts_type_space_candidates(analyzer, candidates)
    }
}

fn jsts_site_for_focus(mut site: ResolvedReferenceSite) -> ResolvedReferenceSite {
    if let Some(reference) = jsts_reference_prefix_for_focus(&site) {
        site.range.end_byte = site.range.start_byte + reference.len();
        site.text = reference;
    }
    site
}

fn jsts_reference_prefix_for_focus(site: &ResolvedReferenceSite) -> Option<String> {
    if !site.text.contains('.') {
        return None;
    }
    let relative_start = site.focus_start_byte.checked_sub(site.range.start_byte)?;
    let relative_end = site.focus_end_byte.checked_sub(site.range.start_byte)?;
    if relative_start >= relative_end || relative_end > site.text.len() {
        return None;
    }

    let mut segment_start = 0;
    for segment in site.text.split('.') {
        let segment_end = segment_start + segment.len();
        if relative_start >= segment_start && relative_end <= segment_end {
            if segment_end == site.text.len() {
                return None;
            }
            return Some(site.text[..segment_end].to_string());
        }
        segment_start = segment_end + 1;
    }
    None
}

fn jsts_member_candidates(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    receiver_candidates: Vec<CodeUnit>,
    member: &str,
    value_position: bool,
) -> Vec<CodeUnit> {
    let mut candidates = Vec::new();
    for receiver in receiver_candidates {
        candidates.extend(support.fqn(&format!("{}.{}", receiver.fq_name(), member)));
    }
    if value_position {
        jsts_value_space_candidates(analyzer, candidates)
    } else {
        jsts_type_space_candidates(analyzer, candidates)
    }
}

fn ts_member_candidates(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    receiver_candidates: Vec<CodeUnit>,
    member: &str,
    value_position: bool,
) -> Vec<CodeUnit> {
    let mut candidates = Vec::new();
    for receiver in receiver_candidates {
        let mut members = support.fqn(&format!("{}.{}", receiver.fq_name(), member));
        if value_position {
            members = jsts_value_space_candidates(analyzer, members);
        } else {
            members = jsts_type_space_candidates(analyzer, members);
        }

        let has_synthetic = members.iter().any(CodeUnit::is_synthetic);
        if has_synthetic
            && !jsts_unit_is_type_only(analyzer, &receiver)
            && !ts_synthetic_member_is_supported_by_receiver_initializer(
                analyzer, support, &receiver, member,
            )
        {
            candidates.extend(members.into_iter().filter(|member| !member.is_synthetic()));
        } else {
            candidates.extend(members);
        }
    }
    candidates
}

fn ts_synthetic_member_is_supported_by_receiver_initializer(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    receiver: &CodeUnit,
    member: &str,
) -> bool {
    let Ok(source) = receiver.source().read_to_string() else {
        return false;
    };
    let Some(tree) = parse_js_ts_tree(receiver.source(), &source, Language::TypeScript) else {
        return false;
    };
    let imports = compute_jsts_import_binder(&source, &tree);
    let aliases = AliasResolver::new(analyzer.project().root().to_path_buf());

    let mut saw_receiver_node = false;
    for node in ts_nodes_for_code_unit(analyzer, receiver, tree.root_node()) {
        let Some(declarator) = ts_variable_declarator_for_unit_node(node, receiver, &source) else {
            continue;
        };
        saw_receiver_node = true;
        let Some(value) = declarator.child_by_field_name("value") else {
            continue;
        };
        let Some(call) =
            ts_unwrap_expression(value, &source).filter(|value| value.kind() == "call_expression")
        else {
            return true;
        };
        let Some(argument_index) =
            ts_call_direct_object_argument_index_with_member(call, &source, member)
        else {
            continue;
        };
        if ts_call_preserves_argument_shape(
            analyzer,
            support,
            receiver.source(),
            &source,
            &imports,
            &aliases,
            call,
            argument_index,
        ) {
            return true;
        }
    }
    let _ = saw_receiver_node;
    false
}

fn ts_variable_declarator_for_unit_node<'tree>(
    node: Node<'tree>,
    unit: &CodeUnit,
    source: &str,
) -> Option<Node<'tree>> {
    if node.kind() == "variable_declarator"
        && node
            .child_by_field_name("name")
            .is_some_and(|name| node_text_matches(name, source, unit.identifier()))
    {
        return Some(node);
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor).find_map(|child| {
        (child.kind() == "variable_declarator"
            && child
                .child_by_field_name("name")
                .is_some_and(|name| node_text_matches(name, source, unit.identifier())))
        .then_some(child)
        .or_else(|| ts_variable_declarator_for_unit_node(child, unit, source))
    })
}

fn ts_call_direct_object_argument_index_with_member(
    call: Node<'_>,
    source: &str,
    member: &str,
) -> Option<usize> {
    let arguments = call.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    arguments
        .named_children(&mut cursor)
        .enumerate()
        .find_map(|(index, argument)| {
            let object = ts_direct_object_literal_value(argument, source)?;
            ts_object_literal_has_member(object, source, member).then_some(index)
        })
}

fn ts_direct_object_literal_value<'tree>(node: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    let node = ts_unwrap_expression(node, source)?;
    (node.kind() == "object").then_some(node)
}

fn ts_unwrap_expression<'tree>(node: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    match node.kind() {
        "as_expression"
        | "satisfies_expression"
        | "type_assertion"
        | "parenthesized_expression" => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .find(|child| {
                    child.kind() != "type_annotation"
                        && child.kind() != "type_identifier"
                        && child.kind() != "predefined_type"
                })
                .and_then(|child| ts_unwrap_expression(child, source))
        }
        _ => Some(node),
    }
}

fn ts_object_literal_has_member(object: Node<'_>, source: &str, member: &str) -> bool {
    let mut cursor = object.walk();
    object
        .named_children(&mut cursor)
        .filter_map(|child| {
            crate::analyzer::typescript::ts_object_literal_property_name(child, source)
        })
        .any(|name| name == member)
}

#[allow(clippy::too_many_arguments)]
fn ts_call_preserves_argument_shape(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    imports: &ImportBinder,
    aliases: &AliasResolver,
    call: Node<'_>,
    argument_index: usize,
) -> bool {
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    ts_call_expression_callees(
        analyzer, support, file, source, imports, aliases, function, 0,
    )
    .into_iter()
    .any(|callee| ts_function_preserves_parameter_shape(analyzer, &callee, argument_index))
}

fn ts_function_preserves_parameter_shape(
    analyzer: &dyn IAnalyzer,
    callee: &CodeUnit,
    parameter_index: usize,
) -> bool {
    let Ok(source) = callee.source().read_to_string() else {
        return false;
    };
    let Some(tree) = parse_js_ts_tree(callee.source(), &source, Language::TypeScript) else {
        return false;
    };
    ts_nodes_for_code_unit(analyzer, callee, tree.root_node())
        .into_iter()
        .any(|node| ts_function_node_preserves_parameter_shape(node, &source, parameter_index))
}

fn ts_function_node_preserves_parameter_shape(
    function: Node<'_>,
    source: &str,
    parameter_index: usize,
) -> bool {
    let Some(parameter_name) = ts_function_parameter_name(function, source, parameter_index) else {
        return false;
    };
    if function.kind() == "arrow_function"
        && let Some(body) = function.child_by_field_name("body")
        && ts_expression_preserves_parameter_shape(body, source, &parameter_name)
    {
        return true;
    }
    ts_function_returns_parameter_shape(function, function.id(), source, &parameter_name)
}

fn ts_function_parameter_name(
    function: Node<'_>,
    source: &str,
    parameter_index: usize,
) -> Option<String> {
    let parameters = function.child_by_field_name("parameters")?;
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .filter_map(ts_parameter_name_node)
        .nth(parameter_index)
        .and_then(|name| source.get(name.start_byte()..name.end_byte()))
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
}

fn ts_function_returns_parameter_shape(
    node: Node<'_>,
    root_id: usize,
    source: &str,
    parameter_name: &str,
) -> bool {
    if node.id() != root_id
        && matches!(
            node.kind(),
            "function_declaration"
                | "function_expression"
                | "arrow_function"
                | "method_definition"
                | "class_declaration"
                | "abstract_class_declaration"
                | "interface_declaration"
        )
    {
        return false;
    }
    if node.kind() == "return_statement" {
        let mut cursor = node.walk();
        return node
            .named_children(&mut cursor)
            .next()
            .is_some_and(|expression| {
                ts_expression_preserves_parameter_shape(expression, source, parameter_name)
            });
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(|child| ts_function_returns_parameter_shape(child, root_id, source, parameter_name))
}

fn ts_expression_preserves_parameter_shape(
    expression: Node<'_>,
    source: &str,
    parameter_name: &str,
) -> bool {
    let Some(expression) = ts_unwrap_expression(expression, source) else {
        return false;
    };
    if matches!(expression.kind(), "identifier" | "property_identifier")
        && node_text_matches(expression, source, parameter_name)
    {
        return true;
    }
    if expression.kind() != "object" {
        return false;
    }
    let mut cursor = expression.walk();
    expression.named_children(&mut cursor).any(|child| {
        child.kind() == "spread_element"
            && child
                .named_child(0)
                .and_then(|spread| ts_unwrap_expression(spread, source))
                .is_some_and(|spread| node_text_matches(spread, source, parameter_name))
    })
}

#[allow(clippy::too_many_arguments)]
fn ts_local_receiver_owner_candidates(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    tree: &Tree,
    site: &ResolvedReferenceSite,
    imports: &ImportBinder,
    aliases: &AliasResolver,
    receiver: &str,
) -> Vec<CodeUnit> {
    ts_receiver_owner_candidates_at_byte(
        analyzer,
        support,
        file,
        source,
        tree.root_node(),
        imports,
        aliases,
        receiver,
        site.focus_start_byte,
    )
}

#[allow(clippy::too_many_arguments)]
fn ts_receiver_owner_candidates_at_byte(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    imports: &ImportBinder,
    aliases: &AliasResolver,
    receiver: &str,
    byte: usize,
) -> Vec<CodeUnit> {
    if receiver == "this"
        && let Some(owner) = jsts_enclosing_class(analyzer, file, byte)
    {
        return vec![owner];
    }
    let Some(scope) = jsts_enclosing_function_scope(root, byte) else {
        return Vec::new();
    };

    let mut candidates = ts_receiver_owners_from_parameters(
        analyzer, support, file, source, imports, aliases, scope, receiver,
    );
    if candidates.is_empty() {
        candidates.extend(ts_receiver_owners_from_contextual_callback(
            analyzer, support, file, source, imports, aliases, scope, receiver,
        ));
    }
    candidates.extend(ts_receiver_owners_from_local_bindings(
        analyzer, support, file, source, imports, aliases, scope, receiver, byte, 0,
    ));
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn jsts_enclosing_class(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    byte: usize,
) -> Option<CodeUnit> {
    let fqn = ClassRangeIndex::build(analyzer, file)
        .enclosing(byte)?
        .to_string();
    analyzer.definitions(&fqn).next().cloned()
}

fn jsts_enclosing_function_scope(root: Node<'_>, byte: usize) -> Option<Node<'_>> {
    let mut current = smallest_named_node_covering(root, byte, byte)?;
    loop {
        if matches!(
            current.kind(),
            "function_declaration" | "function_expression" | "arrow_function" | "method_definition"
        ) {
            return Some(current);
        }
        current = current.parent()?;
    }
}

#[allow(clippy::too_many_arguments)]
fn ts_receiver_owners_from_parameters(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    imports: &ImportBinder,
    aliases: &AliasResolver,
    scope: Node<'_>,
    receiver: &str,
) -> Vec<CodeUnit> {
    let Some(parameters) = scope
        .child_by_field_name("parameters")
        .or_else(|| scope.child_by_field_name("parameter"))
    else {
        return Vec::new();
    };
    let mut owners = Vec::new();
    let mut cursor = parameters.walk();
    for parameter in parameters.named_children(&mut cursor) {
        if !matches!(
            parameter.kind(),
            "required_parameter" | "optional_parameter"
        ) {
            continue;
        }
        let Some(type_node) = parameter.child_by_field_name("type") else {
            continue;
        };
        if parameter
            .child_by_field_name("name")
            .is_some_and(|name| node_text_matches(name, source, receiver))
        {
            owners.extend(ts_resolve_type_text_to_property_owners(
                analyzer,
                support,
                file,
                source,
                imports,
                aliases,
                ts_type_annotation_text(type_node, source).as_str(),
                0,
            ));
            continue;
        }
        if parameter
            .child_by_field_name("pattern")
            .is_some_and(|pattern| ts_object_pattern_binds(pattern, source, receiver))
        {
            let container_owners = ts_resolve_type_text_to_property_owners(
                analyzer,
                support,
                file,
                source,
                imports,
                aliases,
                ts_type_annotation_text(type_node, source).as_str(),
                0,
            );
            let fields =
                jsts_member_candidates(analyzer, support, container_owners, receiver, true);
            for field in fields {
                owners.extend(ts_field_signature_type_owners(
                    analyzer, support, file, source, imports, aliases, &field, 0,
                ));
            }
        }
    }
    owners
}

#[allow(clippy::too_many_arguments)]
fn ts_receiver_owners_from_contextual_callback(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    imports: &ImportBinder,
    aliases: &AliasResolver,
    scope: Node<'_>,
    receiver: &str,
) -> Vec<CodeUnit> {
    let Some(callback_parameter_index) = ts_callback_parameter_index(scope, source, receiver)
    else {
        return Vec::new();
    };
    let Some((call, argument_index)) = ts_callback_argument_context(scope) else {
        return Vec::new();
    };
    let Some(function) = call.child_by_field_name("function") else {
        return Vec::new();
    };
    let callees = ts_call_expression_callees(
        analyzer, support, file, source, imports, aliases, function, 0,
    );

    let mut owners = Vec::new();
    for callee in callees {
        owners.extend(ts_callback_parameter_owners_from_callee(
            analyzer,
            support,
            &callee,
            argument_index,
            callback_parameter_index,
            0,
        ));
    }
    owners
}

fn ts_callback_parameter_index(scope: Node<'_>, source: &str, receiver: &str) -> Option<usize> {
    let parameters = scope
        .child_by_field_name("parameters")
        .or_else(|| scope.child_by_field_name("parameter"))?;
    if parameters.kind() == "identifier" {
        return node_text_matches(parameters, source, receiver).then_some(0);
    }
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .filter_map(|parameter| ts_parameter_name_node(parameter))
        .position(|name| node_text_matches(name, source, receiver))
}

fn ts_parameter_name_node(parameter: Node<'_>) -> Option<Node<'_>> {
    match parameter.kind() {
        "identifier" | "shorthand_property_identifier_pattern" => Some(parameter),
        "required_parameter" | "optional_parameter" => parameter
            .child_by_field_name("pattern")
            .or_else(|| parameter.child_by_field_name("name")),
        _ => None,
    }
}

fn ts_callback_argument_context(scope: Node<'_>) -> Option<(Node<'_>, usize)> {
    let mut current = scope;
    while let Some(parent) = current.parent() {
        if parent.kind() == "arguments" {
            let mut cursor = parent.walk();
            let argument_index = parent
                .named_children(&mut cursor)
                .position(|child| child.id() == current.id())?;
            let call = parent
                .parent()
                .filter(|node| node.kind() == "call_expression")?;
            return Some((call, argument_index));
        }
        current = parent;
    }
    None
}

fn ts_callback_parameter_owners_from_callee(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    callee: &CodeUnit,
    argument_index: usize,
    callback_parameter_index: usize,
    depth: usize,
) -> Vec<CodeUnit> {
    if depth > 8 {
        return Vec::new();
    }
    let Ok(source) = callee.source().read_to_string() else {
        return Vec::new();
    };
    let Some(tree) = parse_js_ts_tree(callee.source(), &source, Language::TypeScript) else {
        return Vec::new();
    };
    let imports = compute_jsts_import_binder(&source, &tree);
    let aliases = AliasResolver::new(analyzer.project().root().to_path_buf());
    let mut owners = Vec::new();
    for node in ts_nodes_for_code_unit(analyzer, callee, tree.root_node()) {
        let Some(callback_type) = ts_function_parameter_type_text(node, &source, argument_index)
        else {
            continue;
        };
        let Some(parameter_type) =
            ts_callback_parameter_type_text(&callback_type, callback_parameter_index)
        else {
            continue;
        };
        owners.extend(ts_resolve_type_text_to_property_owners(
            analyzer,
            support,
            callee.source(),
            &source,
            &imports,
            &aliases,
            &parameter_type,
            depth + 1,
        ));
    }
    owners
}

fn ts_function_parameter_type_text(
    function: Node<'_>,
    source: &str,
    parameter_index: usize,
) -> Option<String> {
    let parameters = function.child_by_field_name("parameters")?;
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .filter(|parameter| {
            matches!(
                parameter.kind(),
                "required_parameter" | "optional_parameter"
            )
        })
        .nth(parameter_index)
        .and_then(|parameter| parameter.child_by_field_name("type"))
        .map(|type_node| ts_type_annotation_text(type_node, source))
}

fn ts_callback_parameter_type_text(callback_type: &str, parameter_index: usize) -> Option<String> {
    let callback_type = callback_type.trim();
    let open = callback_type.find('(')?;
    let close = ts_matching_close_delimiter(callback_type, open, '(', ')')?;
    let parameters = callback_type.get(open + 1..close)?;
    let parameter = ts_split_top_level_commas(parameters)
        .into_iter()
        .nth(parameter_index)?;
    let (_, type_text) = parameter.split_once(':')?;
    Some(ts_clean_type_text(type_text))
}

fn ts_matching_close_delimiter(
    text: &str,
    open_byte: usize,
    open_char: char,
    close_char: char,
) -> Option<usize> {
    let mut depth = 0usize;
    for (index, ch) in text
        .char_indices()
        .skip_while(|(index, _)| *index < open_byte)
    {
        if ch == open_char {
            depth += 1;
        } else if ch == close_char {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn ts_split_top_level_commas(text: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut paren_depth = 0usize;
    let mut angle_depth = 0usize;
    let mut brace_depth = 0usize;
    let mut bracket_depth = 0usize;
    for (index, ch) in text.char_indices() {
        match ch {
            '(' => paren_depth += 1,
            ')' => paren_depth = paren_depth.saturating_sub(1),
            '<' => angle_depth += 1,
            '>' => angle_depth = angle_depth.saturating_sub(1),
            '{' => brace_depth += 1,
            '}' => brace_depth = brace_depth.saturating_sub(1),
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            ',' if paren_depth == 0
                && angle_depth == 0
                && brace_depth == 0
                && bracket_depth == 0 =>
            {
                parts.push(text[start..index].trim());
                start = index + ch.len_utf8();
            }
            _ => {}
        }
    }
    parts.push(text[start..].trim());
    parts
}

#[allow(clippy::too_many_arguments)]
fn ts_receiver_owners_from_local_bindings(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    imports: &ImportBinder,
    aliases: &AliasResolver,
    scope: Node<'_>,
    receiver: &str,
    before_byte: usize,
    depth: usize,
) -> Vec<CodeUnit> {
    if depth > 8 {
        return Vec::new();
    }
    let mut owners = Vec::new();
    ts_collect_receiver_owners_from_bindings(
        analyzer,
        support,
        file,
        source,
        imports,
        aliases,
        scope,
        scope.id(),
        receiver,
        before_byte,
        depth,
        &mut owners,
    );
    owners
}

#[allow(clippy::too_many_arguments)]
fn ts_collect_receiver_owners_from_bindings(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    imports: &ImportBinder,
    aliases: &AliasResolver,
    node: Node<'_>,
    root_id: usize,
    receiver: &str,
    before_byte: usize,
    depth: usize,
    out: &mut Vec<CodeUnit>,
) {
    if node.start_byte() >= before_byte {
        return;
    }
    if node.id() != root_id
        && matches!(
            node.kind(),
            "function_declaration"
                | "function_expression"
                | "arrow_function"
                | "method_definition"
                | "class_declaration"
                | "abstract_class_declaration"
                | "interface_declaration"
        )
    {
        return;
    }

    if node.kind() == "variable_declarator"
        && let Some(name) = node.child_by_field_name("name")
        && node_text_matches(name, source, receiver)
    {
        if let Some(type_node) = node.child_by_field_name("type") {
            out.extend(ts_resolve_type_text_to_property_owners(
                analyzer,
                support,
                file,
                source,
                imports,
                aliases,
                ts_type_annotation_text(type_node, source).as_str(),
                depth + 1,
            ));
        }
        if let Some(value) = node.child_by_field_name("value") {
            out.extend(ts_expression_property_owners(
                analyzer,
                support,
                file,
                source,
                imports,
                aliases,
                value,
                depth + 1,
            ));
        }
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        ts_collect_receiver_owners_from_bindings(
            analyzer,
            support,
            file,
            source,
            imports,
            aliases,
            child,
            root_id,
            receiver,
            before_byte,
            depth,
            out,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn ts_expression_property_owners(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    imports: &ImportBinder,
    aliases: &AliasResolver,
    expression: Node<'_>,
    depth: usize,
) -> Vec<CodeUnit> {
    if depth > 8 {
        return Vec::new();
    }
    match expression.kind() {
        "call_expression" => expression
            .child_by_field_name("function")
            .map(|function| {
                let callees = ts_call_expression_callees(
                    analyzer,
                    support,
                    file,
                    source,
                    imports,
                    aliases,
                    function,
                    depth + 1,
                );
                ts_expand_property_owners(analyzer, support, callees, depth + 1)
            })
            .unwrap_or_default(),
        "await_expression" => {
            let mut cursor = expression.walk();
            expression
                .named_children(&mut cursor)
                .next()
                .map(|child| {
                    ts_expression_property_owners(
                        analyzer,
                        support,
                        file,
                        source,
                        imports,
                        aliases,
                        child,
                        depth + 1,
                    )
                })
                .unwrap_or_default()
        }
        "as_expression" | "satisfies_expression" | "type_assertion" => expression
            .child_by_field_name("type")
            .or_else(|| ts_assertion_type_child(expression))
            .map(|type_node| {
                ts_resolve_type_text_to_property_owners(
                    analyzer,
                    support,
                    file,
                    source,
                    imports,
                    aliases,
                    ts_type_annotation_text(type_node, source).as_str(),
                    depth + 1,
                )
            })
            .unwrap_or_else(|| {
                let mut cursor = expression.walk();
                expression
                    .named_children(&mut cursor)
                    .find(|child| child.kind() != "type_annotation")
                    .map(|child| {
                        ts_expression_property_owners(
                            analyzer,
                            support,
                            file,
                            source,
                            imports,
                            aliases,
                            child,
                            depth + 1,
                        )
                    })
                    .unwrap_or_default()
            }),
        _ => Vec::new(),
    }
}

#[allow(clippy::too_many_arguments)]
fn ts_call_expression_callees(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    imports: &ImportBinder,
    aliases: &AliasResolver,
    function: Node<'_>,
    depth: usize,
) -> Vec<CodeUnit> {
    if depth > 8 {
        return Vec::new();
    }
    if function.kind() == "member_expression" {
        let Some(object) = function.child_by_field_name("object") else {
            return Vec::new();
        };
        let Some(property) = function
            .child_by_field_name("property")
            .and_then(|property| ts_call_reference_name(property, source))
        else {
            return Vec::new();
        };
        if let Some(namespace) = source
            .get(object.start_byte()..object.end_byte())
            .map(str::trim)
            .filter(|namespace| !namespace.is_empty())
            && let Some(binding) = imports.bindings.get(namespace)
            && matches!(
                binding.kind,
                ImportKind::Namespace | ImportKind::CommonJsRequire
            )
        {
            return resolve_js_ts_module_binding_candidates(
                analyzer,
                support,
                Language::TypeScript,
                file,
                &binding.module_specifier,
                &property,
                Some(aliases),
                true,
            );
        }
        let receiver_owners = ts_expression_receiver_owners(
            analyzer,
            support,
            file,
            source,
            imports,
            aliases,
            object,
            depth + 1,
        );
        let callees = jsts_member_candidates(analyzer, support, receiver_owners, &property, true);
        if !callees.is_empty() {
            return callees;
        }
    }

    ts_call_reference_name(function, source)
        .map(|name| {
            ts_identifier_candidates(
                analyzer, support, file, source, imports, aliases, &name, true,
            )
        })
        .unwrap_or_default()
}

#[allow(clippy::too_many_arguments)]
fn ts_expression_receiver_owners(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    imports: &ImportBinder,
    aliases: &AliasResolver,
    expression: Node<'_>,
    depth: usize,
) -> Vec<CodeUnit> {
    if depth > 8 {
        return Vec::new();
    }
    match expression.kind() {
        "identifier" | "property_identifier" | "this" => {
            let Some(receiver) = source
                .get(expression.start_byte()..expression.end_byte())
                .map(str::trim)
            else {
                return Vec::new();
            };
            ts_receiver_owner_candidates_at_byte(
                analyzer,
                support,
                file,
                source,
                root_node(expression),
                imports,
                aliases,
                receiver,
                expression.start_byte(),
            )
        }
        _ => ts_expression_property_owners(
            analyzer,
            support,
            file,
            source,
            imports,
            aliases,
            expression,
            depth + 1,
        ),
    }
}

fn root_node(mut node: Node<'_>) -> Node<'_> {
    while let Some(parent) = node.parent() {
        node = parent;
    }
    node
}

#[allow(clippy::too_many_arguments)]
fn ts_identifier_candidates(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    _source: &str,
    imports: &ImportBinder,
    aliases: &AliasResolver,
    name: &str,
    value_position: bool,
) -> Vec<CodeUnit> {
    let mut candidates = if let Some(binding) = imports.bindings.get(name) {
        let exported_name = match binding.kind {
            ImportKind::Named => binding.imported_name.as_deref().unwrap_or(name),
            ImportKind::Default => "default",
            ImportKind::Namespace | ImportKind::CommonJsRequire | ImportKind::Glob => name,
        };
        if matches!(binding.kind, ImportKind::Named | ImportKind::Default) {
            resolve_js_ts_module_binding_candidates(
                analyzer,
                support,
                Language::TypeScript,
                file,
                &binding.module_specifier,
                exported_name,
                Some(aliases),
                value_position,
            )
        } else {
            Vec::new()
        }
    } else {
        support.file_identifier(file, name)
    };
    if value_position {
        candidates = jsts_value_space_candidates(analyzer, candidates);
    } else {
        candidates = jsts_type_space_candidates(analyzer, candidates);
    }
    candidates
}

#[allow(clippy::too_many_arguments)]
fn ts_resolve_type_text_to_property_owners(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    imports: &ImportBinder,
    aliases: &AliasResolver,
    type_text: &str,
    depth: usize,
) -> Vec<CodeUnit> {
    if depth > 8 {
        return Vec::new();
    }
    let type_text = ts_clean_type_text(type_text);
    if type_text.is_empty() {
        return Vec::new();
    }

    if let Some(name) = ts_typeof_target(&type_text) {
        let candidates = ts_identifier_candidates(
            analyzer, support, file, source, imports, aliases, name, true,
        );
        return ts_expand_property_owners(analyzer, support, candidates, depth + 1);
    }

    if let Some(inner) = ts_generic_type_argument(&type_text, "ReturnType") {
        return ts_resolve_type_text_to_property_owners(
            analyzer,
            support,
            file,
            source,
            imports,
            aliases,
            inner,
            depth + 1,
        );
    }

    if let Some(inner) = ts_generic_type_argument(&type_text, "Promise") {
        return ts_resolve_type_text_to_property_owners(
            analyzer,
            support,
            file,
            source,
            imports,
            aliases,
            inner,
            depth + 1,
        );
    }

    if let Some(inner) = ts_generic_type_argument(&type_text, "z.infer") {
        return ts_resolve_type_text_to_property_owners(
            analyzer,
            support,
            file,
            source,
            imports,
            aliases,
            inner,
            depth + 1,
        );
    }

    let Some(name) = ts_leading_type_identifier(&type_text) else {
        return Vec::new();
    };
    let candidates = ts_identifier_candidates(
        analyzer, support, file, source, imports, aliases, name, false,
    );
    ts_expand_property_owners(analyzer, support, candidates, depth + 1)
}

fn ts_expand_property_owners(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    candidates: Vec<CodeUnit>,
    depth: usize,
) -> Vec<CodeUnit> {
    if depth > 8 {
        return Vec::new();
    }
    let mut owners = Vec::new();
    for candidate in candidates {
        if jsts_unit_is_type_only(analyzer, &candidate) {
            let signatures = analyzer.signatures(&candidate);
            let expanded = signatures
                .iter()
                .flat_map(|signature| {
                    ts_alias_rhs(signature)
                        .map(|rhs| {
                            ts_resolve_type_from_unit_context(
                                analyzer,
                                support,
                                &candidate,
                                rhs,
                                depth + 1,
                            )
                        })
                        .unwrap_or_default()
                })
                .collect::<Vec<_>>();
            if expanded.is_empty() {
                owners.push(candidate);
            } else {
                owners.extend(expanded);
            }
        } else if candidate.is_function() {
            owners.push(candidate.clone());
            owners.extend(ts_function_return_property_owners(
                analyzer,
                support,
                &candidate,
                depth + 1,
            ));
        } else {
            owners.push(candidate);
        }
    }
    sort_units(&mut owners);
    owners.dedup();
    owners
}

fn ts_resolve_type_from_unit_context(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    unit: &CodeUnit,
    type_text: &str,
    depth: usize,
) -> Vec<CodeUnit> {
    let Ok(source) = unit.source().read_to_string() else {
        return Vec::new();
    };
    let Some(tree) = parse_js_ts_tree(unit.source(), &source, Language::TypeScript) else {
        return Vec::new();
    };
    let imports = compute_jsts_import_binder(&source, &tree);
    let aliases = AliasResolver::new(analyzer.project().root().to_path_buf());
    ts_resolve_type_text_to_property_owners(
        analyzer,
        support,
        unit.source(),
        &source,
        &imports,
        &aliases,
        type_text,
        depth + 1,
    )
}

fn ts_function_return_property_owners(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    function: &CodeUnit,
    depth: usize,
) -> Vec<CodeUnit> {
    if depth > 8 {
        return Vec::new();
    }
    let Ok(source) = function.source().read_to_string() else {
        return Vec::new();
    };
    let Some(tree) = parse_js_ts_tree(function.source(), &source, Language::TypeScript) else {
        return Vec::new();
    };
    let imports = compute_jsts_import_binder(&source, &tree);
    let aliases = AliasResolver::new(analyzer.project().root().to_path_buf());
    let mut owners = Vec::new();
    for node in ts_nodes_for_code_unit(analyzer, function, tree.root_node()) {
        if let Some(type_text) = ts_function_return_type_text(node, &source) {
            owners.extend(ts_resolve_type_text_to_property_owners(
                analyzer,
                support,
                function.source(),
                &source,
                &imports,
                &aliases,
                &type_text,
                depth + 1,
            ));
        }
        ts_collect_return_property_owners(
            analyzer,
            support,
            function.source(),
            &source,
            &imports,
            &aliases,
            node,
            node.id(),
            depth + 1,
            &mut owners,
        );
    }
    sort_units(&mut owners);
    owners.dedup();
    owners
}

fn ts_function_return_type_text(function: Node<'_>, source: &str) -> Option<String> {
    function
        .child_by_field_name("return_type")
        .map(|type_node| ts_type_annotation_text(type_node, source))
        .filter(|text| !text.is_empty())
}

fn ts_nodes_for_code_unit<'tree>(
    analyzer: &dyn IAnalyzer,
    unit: &CodeUnit,
    root: Node<'tree>,
) -> Vec<Node<'tree>> {
    let ranges = analyzer.ranges(unit);
    let mut nodes = Vec::new();
    for range in ranges {
        if let Some(node) = smallest_named_node_covering(root, range.start_byte, range.end_byte) {
            nodes.push(
                node.child_by_field_name("declaration")
                    .filter(|_| node.kind() == "export_statement")
                    .unwrap_or(node),
            );
        }
    }
    nodes
}

#[allow(clippy::too_many_arguments)]
fn ts_collect_return_property_owners(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    imports: &ImportBinder,
    aliases: &AliasResolver,
    node: Node<'_>,
    root_id: usize,
    depth: usize,
    out: &mut Vec<CodeUnit>,
) {
    if depth > 8 {
        return;
    }
    if node.id() != root_id
        && matches!(
            node.kind(),
            "function_declaration"
                | "function_expression"
                | "arrow_function"
                | "method_definition"
                | "class_declaration"
                | "abstract_class_declaration"
                | "interface_declaration"
        )
    {
        return;
    }
    if node.kind() == "return_statement" {
        let mut cursor = node.walk();
        if let Some(expression) = node.named_children(&mut cursor).next() {
            out.extend(ts_expression_property_owners(
                analyzer,
                support,
                file,
                source,
                imports,
                aliases,
                expression,
                depth + 1,
            ));
        }
        return;
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        ts_collect_return_property_owners(
            analyzer, support, file, source, imports, aliases, child, root_id, depth, out,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn ts_field_signature_type_owners(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    imports: &ImportBinder,
    aliases: &AliasResolver,
    field: &CodeUnit,
    depth: usize,
) -> Vec<CodeUnit> {
    let mut owners = Vec::new();
    for signature in analyzer.signatures(field) {
        if let Some(type_text) = ts_field_type_text(signature) {
            owners.extend(ts_resolve_type_text_to_property_owners(
                analyzer,
                support,
                file,
                source,
                imports,
                aliases,
                type_text,
                depth + 1,
            ));
        }
    }
    owners
}

fn ts_object_pattern_binds(pattern: Node<'_>, source: &str, receiver: &str) -> bool {
    if pattern.kind() != "object_pattern" {
        return false;
    }
    let mut cursor = pattern.walk();
    pattern
        .named_children(&mut cursor)
        .any(|child| match child.kind() {
            "shorthand_property_identifier_pattern" => node_text_matches(child, source, receiver),
            "pair_pattern" => child
                .child_by_field_name("value")
                .is_some_and(|value| ts_pattern_binds_name(value, source, receiver)),
            _ => false,
        })
}

fn ts_pattern_binds_name(pattern: Node<'_>, source: &str, receiver: &str) -> bool {
    match pattern.kind() {
        "identifier" | "shorthand_property_identifier_pattern" => {
            node_text_matches(pattern, source, receiver)
        }
        "assignment_pattern" => pattern
            .child_by_field_name("left")
            .is_some_and(|left| ts_pattern_binds_name(left, source, receiver)),
        _ => false,
    }
}

fn node_text_matches(node: Node<'_>, source: &str, expected: &str) -> bool {
    source
        .get(node.start_byte()..node.end_byte())
        .is_some_and(|text| text.trim() == expected)
}

fn ts_type_annotation_text(node: Node<'_>, source: &str) -> String {
    ts_clean_type_text(source.get(node.start_byte()..node.end_byte()).unwrap_or(""))
}

fn ts_clean_type_text(text: &str) -> String {
    text.trim()
        .trim_start_matches(':')
        .trim()
        .trim_end_matches(';')
        .trim()
        .to_string()
}

fn ts_field_type_text(signature: &str) -> Option<&str> {
    let (_, rhs) = signature.split_once(':')?;
    Some(
        rhs.split(['=', ','])
            .next()
            .unwrap_or(rhs)
            .trim()
            .trim_end_matches(';')
            .trim(),
    )
}

fn ts_alias_rhs(signature: &str) -> Option<&str> {
    let (_, rhs) = signature.split_once('=')?;
    Some(rhs.trim().trim_end_matches(';').trim())
}

fn ts_typeof_target(text: &str) -> Option<&str> {
    text.trim().strip_prefix("typeof").map(str::trim)
}

fn ts_generic_type_argument<'a>(text: &'a str, generic: &str) -> Option<&'a str> {
    let text = text.trim();
    let rest = text.strip_prefix(generic)?;
    let rest = rest.trim_start();
    let inner = rest.strip_prefix('<')?.strip_suffix('>')?;
    Some(inner.trim())
}

fn ts_leading_type_identifier(text: &str) -> Option<&str> {
    let text = text.trim();
    let end = text
        .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '$'))
        .unwrap_or(text.len());
    (end > 0).then_some(&text[..end])
}

fn ts_call_reference_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" | "property_identifier" => source
            .get(node.start_byte()..node.end_byte())
            .map(|text| text.trim().to_string()),
        "member_expression" => node
            .child_by_field_name("property")
            .and_then(|property| ts_call_reference_name(property, source)),
        _ => None,
    }
}

fn ts_assertion_type_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).find(|child| {
        matches!(
            child.kind(),
            "type_identifier"
                | "generic_type"
                | "type_arguments"
                | "object_type"
                | "predefined_type"
                | "union_type"
                | "intersection_type"
        )
    })
}

fn jsts_reference_is_value_position(tree: &Tree, site: &ResolvedReferenceSite) -> bool {
    let Some(node) =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)
    else {
        return true;
    };
    !jsts_reference_is_type_position(node)
}

fn jsts_reference_is_type_position(mut node: Node<'_>) -> bool {
    loop {
        match node.kind() {
            "type_identifier"
            | "predefined_type"
            | "type_annotation"
            | "type_arguments"
            | "type_parameters"
            | "generic_type"
            | "union_type"
            | "intersection_type"
            | "interface_declaration"
            | "type_alias_declaration"
            | "extends_type_clause"
            | "implements_clause"
            | "constraint" => return true,
            "call_expression"
            | "arguments"
            | "member_expression"
            | "subscript_expression"
            | "binary_expression"
            | "unary_expression"
            | "return_statement"
            | "expression_statement"
            | "variable_declarator"
            | "assignment_expression" => return false,
            _ => {}
        }
        let Some(parent) = node.parent() else {
            return false;
        };
        node = parent;
    }
}

fn jsts_value_space_candidates(
    analyzer: &dyn IAnalyzer,
    candidates: Vec<CodeUnit>,
) -> Vec<CodeUnit> {
    let value_candidates: Vec<_> = candidates
        .iter()
        .filter(|candidate| !jsts_unit_is_type_only(analyzer, candidate))
        .cloned()
        .collect();
    if value_candidates.is_empty() {
        candidates
    } else {
        value_candidates
    }
}

fn jsts_type_space_candidates(
    analyzer: &dyn IAnalyzer,
    candidates: Vec<CodeUnit>,
) -> Vec<CodeUnit> {
    let type_candidates: Vec<_> = candidates
        .iter()
        .filter(|candidate| jsts_unit_is_type_only(analyzer, candidate))
        .cloned()
        .collect();
    if type_candidates.is_empty() {
        candidates
    } else {
        type_candidates
    }
}

fn jsts_unit_is_type_only(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> bool {
    if analyzer
        .type_alias_provider()
        .is_some_and(|provider| provider.is_type_alias(unit))
    {
        return true;
    }
    unit.signature().is_some_and(jsts_signature_is_type_only)
        || analyzer
            .signatures(unit)
            .iter()
            .any(|signature| jsts_signature_is_type_only(signature))
}

fn jsts_signature_is_type_only(signature: &str) -> bool {
    let signature = signature.trim_start();
    signature.starts_with("interface ")
        || signature.starts_with("export interface ")
        || signature.starts_with("declare interface ")
        || signature.starts_with("export declare interface ")
        || signature.starts_with("type ")
        || signature.starts_with("export type ")
        || signature.starts_with("declare type ")
        || signature.starts_with("export declare type ")
}

fn is_bare_js_ts_specifier(module: &str) -> bool {
    !module.starts_with("./") && !module.starts_with("../") && !module.starts_with('/')
}

fn parse_js_ts_tree(file: &ProjectFile, source: &str, language: Language) -> Option<Tree> {
    let mut parser = Parser::new();
    let tree_sitter_language = match language {
        Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        Language::TypeScript if file.rel_path().extension().is_some_and(|ext| ext == "tsx") => {
            tree_sitter_typescript::LANGUAGE_TSX.into()
        }
        Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        _ => return None,
    };
    parser.set_language(&tree_sitter_language).ok()?;
    parser.parse(source, None)
}

fn resolve_go(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    site: &ResolvedReferenceSite,
    graph: Option<&GoProjectGraph>,
) -> DefinitionLookupOutcome {
    let Some(go) = resolve_analyzer::<GoAnalyzer>(analyzer) else {
        return no_definition("go_analyzer_unavailable", "Go analyzer is unavailable");
    };
    let reference = site.text.as_str();
    if let Some(resolution) =
        graph.and_then(|graph| resolve_go_reference(graph, go, file, source, site))
    {
        let candidates = support.fqn_candidates(resolution.fqn_candidates);
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
        if resolution.shadowed {
            if let Some(outcome) =
                resolve_go_local_selector_chain(analyzer, support, file, source, site, reference)
            {
                return outcome;
            }
            return no_definition(
                "no_indexed_definition",
                format!("`{reference}` is shadowed by a local Go binding"),
            );
        }
        if let Some((_, name)) = reference.split_once('.')
            && let Some(package) = resolution.resolved_import_packages.first()
        {
            let candidates = go_package_member_candidates(support, package, name);
            if !candidates.is_empty() {
                return candidates_outcome(candidates);
            }
            if !go_import_path_is_workspace(support, package) {
                return boundary(format!(
                    "`{package}` is outside this partial Go workspace analysis"
                ));
            }
            return no_definition(
                "no_indexed_definition",
                format!("`{name}` is not indexed in Go package `{package}`"),
            );
        }
        if let Some(package) = resolution
            .resolved_import_packages
            .iter()
            .find(|package| !go_import_path_is_workspace(support, package))
        {
            return boundary(format!(
                "`{package}` is outside this partial Go workspace analysis"
            ));
        }
    }

    let package = go_package_name(file, source);
    if let Some((qualifier, name)) = reference.split_once('.') {
        let imports = go_import_paths(go, file);
        if let Some(import_path) = imports.get(qualifier) {
            let candidates = go_package_member_candidates(support, import_path, name);
            if !candidates.is_empty() {
                return candidates_outcome(candidates);
            }
            if !go_import_path_is_workspace(support, import_path) {
                return boundary(format!(
                    "`{import_path}` is outside this partial Go workspace analysis"
                ));
            }
            return no_definition(
                "no_indexed_definition",
                format!("`{name}` is not indexed in Go package `{import_path}`"),
            );
        }
        if let Some(outcome) =
            resolve_go_local_selector_chain(analyzer, support, file, source, site, reference)
        {
            return outcome;
        }
        let candidates = support.fqn_candidates([format!("{package}.{qualifier}.{name}")]);
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
        return no_definition(
            "no_indexed_definition",
            format!("`{reference}` did not resolve to an indexed Go definition"),
        );
    }

    let candidates = go_package_member_candidates(support, &package, reference);
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }
    let same_file = support.file_identifier(file, reference);
    if !same_file.is_empty() {
        return candidates_outcome(same_file);
    }
    if let Some(import_path) = go_external_dot_import_path(go, support, file) {
        return boundary(format!(
            "`{import_path}` is outside this partial Go workspace analysis"
        ));
    }
    no_definition(
        "no_indexed_definition",
        format!("`{reference}` did not resolve to an indexed Go definition"),
    )
}

fn go_package_name(file: &ProjectFile, source: &str) -> String {
    let declared = source
        .lines()
        .find_map(|line| line.trim().strip_prefix("package "))
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or("");
    crate::analyzer::go::packages::canonical_go_package_name(file, declared)
}

fn go_import_paths(
    go: &crate::analyzer::GoAnalyzer,
    file: &ProjectFile,
) -> HashMap<String, String> {
    let mut imports = HashMap::default();
    for import in go.import_info_of(file) {
        if matches!(import.alias.as_deref(), Some("_") | Some(".")) {
            continue;
        }
        let Some(import_path) = extract_go_import_path(&import.raw_snippet) else {
            continue;
        };
        let local = import
            .alias
            .as_deref()
            .map(default_go_import_local_name)
            .or_else(|| {
                import
                    .identifier
                    .as_deref()
                    .map(default_go_import_local_name)
            })
            .unwrap_or_else(|| default_go_import_local_name(&import_path));
        imports.insert(local, import_path);
    }
    imports
}

fn go_import_path_is_workspace(support: &DefinitionLookupIndex, import_path: &str) -> bool {
    support.fqn_prefix_exists(import_path)
}

fn go_package_member_candidates(
    support: &DefinitionLookupIndex,
    package: &str,
    name: &str,
) -> Vec<CodeUnit> {
    let mut candidates = support.fqn(&format!("{package}.{name}"));
    candidates.extend(support.fqn(&format!("{package}._module_.{name}")));
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn go_external_dot_import_path(
    go: &crate::analyzer::GoAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
) -> Option<String> {
    go.import_info_of(file).iter().find_map(|import| {
        (import.alias.as_deref() == Some("."))
            .then(|| extract_go_import_path(&import.raw_snippet))
            .flatten()
            .filter(|import_path| !go_import_path_is_workspace(support, import_path))
    })
}

fn resolve_go_local_selector_chain(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    site: &ResolvedReferenceSite,
    reference: &str,
) -> Option<DefinitionLookupOutcome> {
    let segments: Vec<_> = reference.split('.').collect();
    if segments.len() < 2 {
        return None;
    }

    let mut parser = Parser::new();
    parser.set_language(&tree_sitter_go::LANGUAGE.into()).ok()?;
    let tree = parser.parse(source, None)?;
    let mut owner_fqn = go_binding_type_fqn(
        analyzer,
        support,
        file,
        source,
        tree.root_node(),
        segments[0],
        site.focus_start_byte,
    )?;
    let mut deepest_workspace_field = None;
    for (index, member) in segments[1..].iter().enumerate() {
        let candidates = support.fqn(&format!("{owner_fqn}.{member}"));
        if !candidates.is_empty() {
            deepest_workspace_field = Some(candidates.clone());
        }
        if index == segments.len() - 2 {
            return if candidates.is_empty() {
                deepest_workspace_field
                    .map(|candidates| go_partial_selector_chain_outcome(candidates, member))
            } else {
                Some(candidates_outcome(candidates))
            };
        }
        let Some(next_owner) = go_indexed_field_type_fqn(analyzer, support, &owner_fqn, member)
        else {
            return deepest_workspace_field
                .map(|candidates| go_partial_selector_chain_outcome(candidates, member));
        };
        owner_fqn = next_owner;
    }
    None
}

fn go_partial_selector_chain_outcome(
    candidates: Vec<CodeUnit>,
    missing_member: &str,
) -> DefinitionLookupOutcome {
    let mut outcome = candidates_outcome(candidates);
    outcome.diagnostics.push(DefinitionLookupDiagnostic {
        kind: "partial_selector_chain".to_string(),
        message: format!(
            "resolved the deepest indexed Go workspace field before `{missing_member}`"
        ),
    });
    outcome
}

fn go_binding_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    name: &str,
    byte: usize,
) -> Option<String> {
    go_receiver_binding_type_fqn(support, file, source, root, name, byte)
        .or_else(|| go_local_binding_type_fqn(analyzer, support, file, source, root, name, byte))
}

fn go_receiver_binding_type_fqn(
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    name: &str,
    byte: usize,
) -> Option<String> {
    let mut current = smallest_named_node_covering(root, byte, byte)?;
    loop {
        if current.kind() == "method_declaration"
            && let Some(receiver) = current.child_by_field_name("receiver")
            && let Some(type_node) = go_parameter_type_for_name(receiver, source, name)
        {
            return go_resolve_type_fqn(support, file, source, type_node);
        }
        current = current.parent()?;
    }
}

/// The type a local `name` is bound to, resolved by walking the parsed AST
/// outward from `byte`. Each enclosing scope is searched for the nearest
/// preceding `:=` or `var` declaration of `name`; the innermost match wins, so
/// shadowing is respected. An `if`/`for` initializer is a named child of the
/// statement node we walk through, so those bindings are covered too.
fn go_local_binding_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    name: &str,
    byte: usize,
) -> Option<String> {
    let mut scope = smallest_named_node_covering(root, byte, byte)?;
    loop {
        if let Some(binding) = go_nearest_binding_in_scope(scope, source, name, byte) {
            let resolved = match binding {
                GoLocalBinding::Type(type_node) => {
                    go_resolve_type_fqn(support, file, source, type_node)
                }
                GoLocalBinding::Value(value_node) => {
                    go_value_type_fqn(analyzer, support, file, source, root, value_node, byte)
                }
                GoLocalBinding::RangeElement(range_node) => go_range_binding_type_fqn(
                    analyzer, support, file, source, root, range_node, byte,
                ),
            };
            if resolved.is_some() {
                return resolved;
            }
        }
        scope = scope.parent()?;
    }
}

/// How a local binding names its type: an explicit `var x T` annotation, or the
/// value expression of an inferred `x := value` binding to derive it from.
enum GoLocalBinding<'tree> {
    Type(Node<'tree>),
    Value(Node<'tree>),
    RangeElement(Node<'tree>),
}

fn go_nearest_binding_in_scope<'tree>(
    scope: Node<'tree>,
    source: &str,
    name: &str,
    byte: usize,
) -> Option<GoLocalBinding<'tree>> {
    let mut cursor = scope.walk();
    let mut nearest: Option<(usize, GoLocalBinding<'tree>)> = None;
    for child in scope.named_children(&mut cursor) {
        if child.end_byte() > byte {
            continue;
        }
        let binding = match child.kind() {
            "parameter_list" => go_parameter_list_binding(child, source, name),
            "short_var_declaration" => go_short_var_binding(child, source, name),
            "var_declaration" => go_var_declaration_binding(child, source, name),
            "range_clause" => go_range_binding(child, source, name),
            _ => None,
        };
        if let Some(binding) = binding
            && nearest
                .as_ref()
                .is_none_or(|(start, _)| child.start_byte() > *start)
        {
            nearest = Some((child.start_byte(), binding));
        }
    }
    nearest.map(|(_, binding)| binding)
}

fn go_parameter_list_binding<'tree>(
    node: Node<'tree>,
    source: &str,
    name: &str,
) -> Option<GoLocalBinding<'tree>> {
    let mut cursor = node.walk();
    for parameter in node.named_children(&mut cursor) {
        if parameter.kind() != "parameter_declaration" {
            continue;
        }
        let Some(type_node) = go_parameter_type_for_name(parameter, source, name) else {
            continue;
        };
        return Some(GoLocalBinding::Type(type_node));
    }
    None
}

fn go_range_binding<'tree>(
    node: Node<'tree>,
    source: &str,
    name: &str,
) -> Option<GoLocalBinding<'tree>> {
    let left = node.child_by_field_name("left")?;
    let index = go_expression_list_index(left, source, name)?;
    (index == 1).then_some(GoLocalBinding::RangeElement(node))
}

fn go_short_var_binding<'tree>(
    node: Node<'tree>,
    source: &str,
    name: &str,
) -> Option<GoLocalBinding<'tree>> {
    let left = node.child_by_field_name("left")?;
    let index = go_expression_list_index(left, source, name)?;
    let right = node.child_by_field_name("right")?;
    go_expression_list_item(right, index).map(GoLocalBinding::Value)
}

fn go_var_declaration_binding<'tree>(
    node: Node<'tree>,
    source: &str,
    name: &str,
) -> Option<GoLocalBinding<'tree>> {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        // `var x T` holds a `var_spec` directly; `var ( ... )` wraps each spec.
        let found = if child.kind() == "var_spec" {
            go_var_spec_binding(child, source, name)
        } else {
            let mut inner = child.walk();
            child
                .named_children(&mut inner)
                .filter(|spec| spec.kind() == "var_spec")
                .find_map(|spec| go_var_spec_binding(spec, source, name))
        };
        if found.is_some() {
            return found;
        }
    }
    None
}

fn go_var_spec_binding<'tree>(
    spec: Node<'tree>,
    source: &str,
    name: &str,
) -> Option<GoLocalBinding<'tree>> {
    let index = go_named_identifier_index(spec, source, name)?;
    if let Some(type_node) = spec.child_by_field_name("type") {
        return Some(GoLocalBinding::Type(type_node));
    }
    let value_list = spec.child_by_field_name("value")?;
    go_expression_list_item(value_list, index).map(GoLocalBinding::Value)
}

fn go_named_identifier_index(spec: Node<'_>, source: &str, name: &str) -> Option<usize> {
    let mut cursor = spec.walk();
    spec.named_children(&mut cursor)
        .filter(|child| child.kind() == "identifier")
        .position(|child| go_node_text(child, source).trim() == name)
}

fn go_expression_list_index(list: Node<'_>, source: &str, name: &str) -> Option<usize> {
    let mut cursor = list.walk();
    list.named_children(&mut cursor)
        .position(|child| go_node_text(child, source).trim() == name)
}

fn go_expression_list_item<'tree>(list: Node<'tree>, index: usize) -> Option<Node<'tree>> {
    if list.kind() == "expression_list" {
        let mut cursor = list.walk();
        list.named_children(&mut cursor).nth(index)
    } else {
        (index == 0).then_some(list)
    }
}

fn go_first_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).next()
}

fn go_last_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).last()
}

fn go_type_text_from_composite_value(value: &str) -> Option<&str> {
    let trimmed = value
        .trim_start_matches('&')
        .trim_start_matches('*')
        .trim_start();
    let end = trimmed.find(['{', '(']).unwrap_or(trimmed.len());
    let type_text = trimmed[..end].trim();
    (!type_text.is_empty()).then_some(type_text)
}

fn go_value_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    value_node: Node<'_>,
    byte: usize,
) -> Option<String> {
    go_value_type_text(analyzer, support, file, source, root, value_node, byte)
        .and_then(|type_text| go_resolve_type_text_fqn(support, file, source, &type_text))
}

fn go_value_type_text(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    value_node: Node<'_>,
    byte: usize,
) -> Option<String> {
    match value_node.kind() {
        "selector_expression" => go_selector_expression_type_text(
            analyzer, support, file, source, root, value_node, byte,
        ),
        "call_expression" => go_call_expression_return_type_text(
            analyzer, support, file, source, root, value_node, byte,
        ),
        "identifier" => {
            go_identifier_value_type_fqn(analyzer, support, file, source, root, value_node, byte)
                .and_then(|fqn| go_type_text_from_fqn(&fqn).map(str::to_string))
        }
        _ => {
            go_type_text_from_composite_value(go_node_text(value_node, source)).map(str::to_string)
        }
    }
}

fn go_identifier_value_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    value_node: Node<'_>,
    byte: usize,
) -> Option<String> {
    matches!(value_node.kind(), "identifier").then_some(())?;
    let identifier = go_node_text(value_node, source).trim();
    go_binding_type_fqn(
        analyzer,
        support,
        file,
        source,
        root,
        identifier,
        byte.min(value_node.start_byte()),
    )
}

fn go_selector_value_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    value_node: Node<'_>,
    byte: usize,
) -> Option<String> {
    if value_node.kind() != "selector_expression" {
        return None;
    }
    let qualifier_node = go_first_named_child(value_node)?;
    let field_node = go_last_named_child(value_node)?;
    let field = go_node_text(field_node, source).trim();
    let qualifier_type = go_expression_type_fqn(
        analyzer,
        support,
        file,
        source,
        root,
        qualifier_node,
        byte.min(value_node.start_byte()),
    )?;
    let (field_file, type_text) = go_indexed_field_type(analyzer, support, &qualifier_type, field)?;
    go_resolve_go_field_type_fqn(analyzer, support, &qualifier_type, &field_file, &type_text)
}

fn go_expression_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
    byte: usize,
) -> Option<String> {
    match expression.kind() {
        "identifier" => go_binding_type_fqn(
            analyzer,
            support,
            file,
            source,
            root,
            go_node_text(expression, source).trim(),
            byte,
        ),
        "selector_expression" => {
            go_selector_value_type_fqn(analyzer, support, file, source, root, expression, byte)
        }
        "parenthesized_expression" | "unary_expression" => {
            let mut cursor = expression.walk();
            expression.named_children(&mut cursor).find_map(|child| {
                go_expression_type_fqn(analyzer, support, file, source, root, child, byte)
            })
        }
        _ => None,
    }
}

fn go_range_binding_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    range_node: Node<'_>,
    byte: usize,
) -> Option<String> {
    let right = range_node
        .child_by_field_name("right")
        .or_else(|| go_last_named_child(range_node))?;
    let iterable_type =
        go_expression_type_text(analyzer, support, file, source, root, right, byte)?;
    let element_type = go_iterable_element_type_text(&iterable_type)?;
    go_resolve_type_text_fqn(support, file, source, element_type)
}

fn go_expression_type_text(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
    byte: usize,
) -> Option<String> {
    match expression.kind() {
        "identifier" => {
            let binding =
                go_nearest_visible_binding(root, source, go_node_text(expression, source), byte)?;
            match binding {
                GoLocalBinding::Type(type_node) => {
                    Some(go_node_text(type_node, source).to_string())
                }
                GoLocalBinding::Value(value_node) => {
                    go_value_type_text(analyzer, support, file, source, root, value_node, byte)
                }
                GoLocalBinding::RangeElement(range_node) => go_range_binding_type_fqn(
                    analyzer, support, file, source, root, range_node, byte,
                )
                .and_then(|fqn| go_type_text_from_fqn(&fqn).map(str::to_string)),
            }
        }
        "selector_expression" => go_selector_expression_type_text(
            analyzer, support, file, source, root, expression, byte,
        ),
        _ => {
            go_type_text_from_composite_value(go_node_text(expression, source)).map(str::to_string)
        }
    }
}

fn go_selector_expression_type_text(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
    byte: usize,
) -> Option<String> {
    let qualifier_node = go_first_named_child(expression)?;
    let field_node = go_last_named_child(expression)?;
    let field = go_node_text(field_node, source).trim();
    let qualifier_type = go_expression_type_fqn(
        analyzer,
        support,
        file,
        source,
        root,
        qualifier_node,
        byte.min(expression.start_byte()),
    )?;
    go_indexed_field_type(analyzer, support, &qualifier_type, field)
        .map(|(_, type_text)| type_text.trim().to_string())
}

fn go_call_expression_return_type_text(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
    byte: usize,
) -> Option<String> {
    if expression.kind() != "call_expression" {
        return None;
    }
    let function = expression
        .child_by_field_name("function")
        .or_else(|| go_first_named_child(expression))?;
    match function.kind() {
        "selector_expression" => {
            let qualifier_node = go_first_named_child(function)?;
            let method_node = go_last_named_child(function)?;
            let owner_fqn = go_expression_type_fqn(
                analyzer,
                support,
                file,
                source,
                root,
                qualifier_node,
                byte.min(expression.start_byte()),
            )?;
            let method = go_node_text(method_node, source).trim();
            go_callable_return_type_text(analyzer, support.fqn(&format!("{owner_fqn}.{method}")))
        }
        "identifier" => {
            let package = go_package_name(file, source);
            let name = go_node_text(function, source).trim();
            go_callable_return_type_text(
                analyzer,
                go_package_member_candidates(support, &package, name),
            )
        }
        _ => None,
    }
}

fn go_callable_return_type_text(
    analyzer: &dyn IAnalyzer,
    candidates: Vec<CodeUnit>,
) -> Option<String> {
    candidates.into_iter().find_map(|candidate| {
        for signature in analyzer.signatures(&candidate) {
            if let Some(return_type) = go_function_return_type_text(signature) {
                return Some(return_type.to_string());
            }
        }
        candidate
            .signature()
            .and_then(go_function_return_type_text)
            .map(str::to_string)
    })
}

fn go_function_return_type_text(signature: &str) -> Option<&str> {
    let header = signature.split('{').next().unwrap_or(signature).trim();
    let rest = header.strip_prefix("func")?.trim_start();
    let rest = if rest.starts_with('(') {
        let receiver_end = go_matching_close_paren(rest, 0)?;
        rest.get(receiver_end + 1..)?.trim_start()
    } else {
        rest
    };
    let params_start = rest.find('(')?;
    let params_end = go_matching_close_paren(rest, params_start)?;
    let return_type = rest.get(params_end + 1..)?.trim();
    (!return_type.is_empty()).then_some(return_type)
}

fn go_matching_close_paren(text: &str, open_byte: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (index, ch) in text
        .char_indices()
        .skip_while(|(index, _)| *index < open_byte)
    {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn go_nearest_visible_binding<'tree>(
    root: Node<'tree>,
    source: &str,
    name: &str,
    byte: usize,
) -> Option<GoLocalBinding<'tree>> {
    let mut scope = smallest_named_node_covering(root, byte, byte)?;
    loop {
        if let Some(binding) = go_nearest_binding_in_scope(scope, source, name.trim(), byte) {
            return Some(binding);
        }
        scope = scope.parent()?;
    }
}

fn go_iterable_element_type_text(type_text: &str) -> Option<&str> {
    let trimmed = type_text.trim();
    trimmed
        .strip_prefix("[]")
        .or_else(|| {
            trimmed.strip_prefix("map[").and_then(|rest| {
                let close = rest.find(']')?;
                Some(rest[close + 1..].trim())
            })
        })
        .filter(|value| !value.is_empty())
}

fn go_type_text_from_fqn(fqn: &str) -> Option<&str> {
    fqn.rsplit_once('.').map(|(_, name)| name)
}

fn go_resolve_type_text_fqn(
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    type_text: &str,
) -> Option<String> {
    let (qualifier, name) = go_type_name_parts(type_text)?;
    if qualifier.is_some() {
        return None;
    }
    go_resolve_type_name_in_package(support, &go_package_name(file, source), name)
}

fn go_parameter_type_for_name<'tree>(
    parameter_list: Node<'tree>,
    source: &str,
    name: &str,
) -> Option<Node<'tree>> {
    if parameter_list.kind() == "parameter_declaration" {
        return go_parameter_declaration_type_for_name(parameter_list, source, name);
    }
    let mut cursor = parameter_list.walk();
    for parameter in parameter_list.named_children(&mut cursor) {
        if parameter.kind() != "parameter_declaration" {
            continue;
        }
        let type_node = go_parameter_declaration_type_for_name(parameter, source, name);
        if type_node.is_some() {
            return type_node;
        }
    }
    None
}

fn go_parameter_declaration_type_for_name<'tree>(
    parameter: Node<'tree>,
    source: &str,
    name: &str,
) -> Option<Node<'tree>> {
    let mut names = Vec::new();
    let mut type_node = None;
    let mut inner = parameter.walk();
    for child in parameter.named_children(&mut inner) {
        match child.kind() {
            "identifier" => names.push(go_node_text(child, source)),
            _ => type_node = Some(child),
        }
    }
    names.contains(&name).then_some(type_node).flatten()
}

fn go_indexed_field_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    owner_fqn: &str,
    field: &str,
) -> Option<String> {
    let (field_file, type_text) = go_indexed_field_type(analyzer, support, owner_fqn, field)?;
    go_resolve_go_field_type_fqn(analyzer, support, owner_fqn, &field_file, &type_text)
}

fn go_indexed_field_type(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    owner_fqn: &str,
    field: &str,
) -> Option<(ProjectFile, String)> {
    let field_unit = support
        .fqn(&format!("{owner_fqn}.{field}"))
        .into_iter()
        .next()?;
    let signature = field_unit
        .signature()
        .map(str::to_string)
        .or_else(|| analyzer.signatures(&field_unit).iter().next().cloned())?;
    let type_text = signature
        .trim()
        .strip_prefix(field)
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    Some((field_unit.source().clone(), type_text.to_string()))
}

fn go_resolve_go_field_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    owner_fqn: &str,
    field_file: &ProjectFile,
    type_text: &str,
) -> Option<String> {
    if let Some(fqn) = go_resolve_qualified_type_from_file(analyzer, support, field_file, type_text)
    {
        return Some(fqn);
    }
    let package = owner_fqn.rsplit_once('.').map(|(package, _)| package)?;
    go_resolve_type_name_in_package(support, package, type_text)
}

fn go_resolve_qualified_type_from_file(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    type_text: &str,
) -> Option<String> {
    let (Some(qualifier), name) = go_type_name_parts(type_text)? else {
        return None;
    };
    let go = resolve_analyzer::<GoAnalyzer>(analyzer)?;
    let import_path = go_import_paths(go, file).remove(qualifier)?;
    let fqn = format!("{import_path}.{name}");
    support.fqn_exists(&fqn).then_some(fqn)
}

fn go_resolve_type_fqn(
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    type_node: Node<'_>,
) -> Option<String> {
    go_resolve_type_name_in_package(
        support,
        &go_package_name(file, source),
        go_node_text(type_node, source),
    )
}

fn go_resolve_type_name_in_package(
    support: &DefinitionLookupIndex,
    package: &str,
    type_text: &str,
) -> Option<String> {
    let name = go_simple_type_name(type_text)?;
    let fqn = format!("{package}.{name}");
    support.fqn_exists(&fqn).then_some(fqn)
}

fn go_simple_type_name(type_text: &str) -> Option<&str> {
    go_type_name_parts(type_text).map(|(_, name)| name)
}

fn go_type_name_parts(type_text: &str) -> Option<(Option<&str>, &str)> {
    let trimmed = type_text
        .trim()
        .trim_start_matches('*')
        .trim_start_matches("[]")
        .trim();
    let raw = trimmed
        .split(['[', '{', ' ', '\t', '\n', '\r'])
        .next()
        .unwrap_or(trimmed);
    let (qualifier, name) = raw
        .rsplit_once('.')
        .map(|(qualifier, name)| (Some(qualifier.trim()), name))
        .unwrap_or((None, raw));
    let name = name.trim();
    (!name.is_empty()).then_some((qualifier.filter(|value| !value.is_empty()), name))
}

fn go_node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or_default()
        .trim()
}

fn resolve_cpp(
    analyzer: &dyn IAnalyzer,
    context: &mut DefinitionBatchContext<'_>,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    let Some(cpp) = resolve_analyzer::<CppAnalyzer>(analyzer) else {
        return no_definition("cpp_analyzer_unavailable", "C++ analyzer is unavailable");
    };
    let Some(tree) = tree else {
        return no_definition("cpp_parse_failed", "C++ source could not be parsed");
    };
    let visibility = context.cpp_visibility(cpp, analyzer, file);
    let support = context.support;
    let root = tree.root_node();
    let Some(node) = smallest_named_node_covering(root, site.focus_start_byte, site.focus_end_byte)
    else {
        return no_definition(
            "no_indexed_definition",
            format!(
                "`{}` did not resolve to an indexed C++ definition",
                site.text
            ),
        );
    };
    let ctx = CppLookupCtx {
        analyzer,
        support,
        file,
        visibility: visibility.as_ref(),
        source,
        root,
    };
    match cpp_reference_node(node) {
        Some(CppReferenceNode::Type(type_node)) => {
            if cpp_is_type_declaration_name(node) {
                return no_definition(
                    "declaration_or_import_site",
                    format!("`{}` is not a C++ reference site", site.text),
                );
            }
            resolve_cpp_type(
                analyzer,
                support,
                file,
                ctx.visibility,
                ctx.source,
                type_node,
            )
        }
        Some(CppReferenceNode::Call(call)) => resolve_cpp_call(ctx, call),
        Some(CppReferenceNode::Field(field)) => resolve_cpp_field(ctx, field, None, None),
        Some(CppReferenceNode::Identifier(identifier)) => {
            if cpp_is_declaration_name(node) {
                return no_definition(
                    "declaration_or_import_site",
                    format!("`{}` is not a C++ reference site", site.text),
                );
            }
            let text = cpp_node_text(identifier, ctx.source);
            if text.is_empty() {
                return no_definition("no_reference_text", "C++ identifier is blank");
            }
            let bindings = cpp_local_bindings_before(
                ctx.analyzer,
                ctx.support,
                ctx.visibility,
                ctx.file,
                ctx.source,
                ctx.root,
                identifier,
                identifier.start_byte(),
            );
            if bindings.is_shadowed(text) {
                return no_definition(
                    "local_variable_reference",
                    format!("`{text}` is a local C++ value"),
                );
            }
            if let Some(owner) =
                cpp_enclosing_class(ctx.analyzer, ctx.file, ctx.source, identifier.start_byte())
            {
                let member_candidates = cpp_member_candidates(ctx, vec![owner], text, None, None)
                    .into_iter()
                    .filter(|unit| unit.is_field())
                    .collect::<Vec<_>>();
                if !member_candidates.is_empty() {
                    return candidates_outcome(member_candidates);
                }
            }
            let candidates = ctx
                .support
                .file_identifier(ctx.file, text)
                .into_iter()
                .filter(|unit| {
                    cpp_unit_matches_kind(
                        ctx.analyzer,
                        ctx.support,
                        unit,
                        CppTargetKind::GlobalField,
                    )
                })
                .collect::<Vec<_>>();
            if !candidates.is_empty() {
                return candidates_outcome(candidates);
            }
            let candidates = cpp_visible_name_candidates(
                ctx.analyzer,
                ctx.visibility,
                ctx.file,
                ctx.support,
                text,
                Some(CppTargetKind::GlobalField),
                cpp_lexical_namespace(identifier, ctx.source).as_deref(),
            );
            if !candidates.is_empty() {
                return candidates_outcome(candidates);
            }
            no_definition(
                "no_indexed_definition",
                format!("`{text}` did not resolve to an indexed C++ definition"),
            )
        }
        None => no_definition(
            "unsupported_cpp_reference_shape",
            format!(
                "`{}` is a C++ `{}` reference shape that get_definition does not resolve yet",
                site.text,
                node.kind()
            ),
        ),
    }
}

fn parse_cpp_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .ok()?;
    parser.parse(source, None)
}

enum CppReferenceNode<'tree> {
    Type(Node<'tree>),
    Call(Node<'tree>),
    Field(Node<'tree>),
    Identifier(Node<'tree>),
}

#[derive(Clone, Copy)]
struct CppLookupCtx<'a, 'tree> {
    analyzer: &'a dyn IAnalyzer,
    support: &'a DefinitionLookupIndex,
    file: &'a ProjectFile,
    visibility: &'a CppVisibilityIndex,
    source: &'a str,
    root: Node<'tree>,
}

fn cpp_reference_node(node: Node<'_>) -> Option<CppReferenceNode<'_>> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "qualified_identifier"
            && (parent.child_by_field_name("name") == Some(current)
                || parent.child_by_field_name("scope") == Some(current))
        {
            current = parent;
            continue;
        }
        if parent.kind() == "field_expression"
            && parent.child_by_field_name("field") == Some(current)
        {
            current = parent;
            continue;
        }
        if parent.kind() == "call_expression"
            && parent.child_by_field_name("function") == Some(current)
        {
            current = parent;
            continue;
        }
        break;
    }

    match current.kind() {
        "call_expression" => Some(CppReferenceNode::Call(current)),
        "field_expression" => Some(CppReferenceNode::Field(current)),
        "type_identifier" | "qualified_identifier" | "template_type" | "scoped_type_identifier" => {
            Some(CppReferenceNode::Type(current))
        }
        "identifier" | "field_identifier" => Some(CppReferenceNode::Identifier(current)),
        _ => None,
    }
}

fn cpp_is_type_declaration_name(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    parent.child_by_field_name("name") == Some(node)
        && matches!(
            parent.kind(),
            "class_specifier"
                | "struct_specifier"
                | "union_specifier"
                | "enum_specifier"
                | "alias_declaration"
                | "type_definition"
        )
}

fn resolve_cpp_type(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    visibility: &CppVisibilityIndex,
    source: &str,
    node: Node<'_>,
) -> DefinitionLookupOutcome {
    let text = normalize_cpp_type_text(cpp_node_text(node, source));
    if text.is_empty() {
        return no_definition("no_reference_text", "C++ type reference is blank");
    }
    if cpp_qualified_identifier_is_declaration_name(node) {
        return no_definition(
            "declaration_or_import_site",
            format!("`{text}` is not a C++ reference site"),
        );
    }
    if node.kind() == "qualified_identifier"
        && let (Some(scope), Some(name)) = (
            node.child_by_field_name("scope"),
            node.child_by_field_name("name"),
        )
        && let Some(owner) = visibility.resolve_type(file, cpp_node_text(scope, source))
    {
        let candidates =
            cpp_direct_member_candidates(support, &[owner], cpp_node_text(name, source));
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
    }
    if let Some(unit) = visibility.resolve_type(file, &text) {
        let candidates = support.fqn(&unit.fq_name());
        return if candidates.is_empty() {
            candidates_outcome(vec![unit])
        } else {
            candidates_outcome(candidates)
        };
    }
    let namespace = cpp_lexical_namespace(node, source);
    let candidates = cpp_visible_name_candidates(
        analyzer,
        visibility,
        file,
        support,
        &text,
        Some(CppTargetKind::Type),
        namespace.as_deref(),
    );
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }
    if cpp_unresolved_include_boundary(analyzer, file, &text) {
        return boundary(format!(
            "`{text}` appears to cross a C++ include boundary not indexed in this workspace"
        ));
    }
    no_definition(
        "no_indexed_definition",
        format!("`{text}` did not resolve to an indexed C++ type"),
    )
}

fn resolve_cpp_call(ctx: CppLookupCtx<'_, '_>, call: Node<'_>) -> DefinitionLookupOutcome {
    let Some(function) = call.child_by_field_name("function") else {
        return no_definition("no_function_name", "C++ call expression has no function");
    };
    let call_arity = cpp_call_arity(call);
    let call_arg_types = cpp_call_argument_types(
        ctx.analyzer,
        ctx.support,
        ctx.visibility,
        ctx.file,
        ctx.source,
        ctx.root,
        call,
    );
    match function.kind() {
        "field_expression" => {
            resolve_cpp_field(ctx, function, Some(call_arity), call_arg_types.as_deref())
        }
        "qualified_identifier" => {
            let text = cpp_node_text(function, ctx.source);
            let mut candidates = cpp_visible_name_candidates(
                ctx.analyzer,
                ctx.visibility,
                ctx.file,
                ctx.support,
                text,
                Some(CppTargetKind::FreeFunction),
                cpp_lexical_namespace(function, ctx.source).as_deref(),
            );
            if !candidates.is_empty() {
                candidates = cpp_filter_candidates_by_call(
                    candidates,
                    Some(call_arity),
                    call_arg_types.as_deref(),
                    ctx.analyzer,
                    ctx.visibility,
                    ctx.file,
                );
                return candidates_outcome(candidates);
            }
            if let Some(scope) = function.child_by_field_name("scope")
                && let Some(name) = function.child_by_field_name("name")
            {
                let member = cpp_node_text(name, ctx.source);
                if let Some(owner) = ctx
                    .visibility
                    .resolve_type(ctx.file, cpp_node_text(scope, ctx.source))
                {
                    candidates = cpp_member_candidates(
                        ctx,
                        vec![owner],
                        member,
                        Some(call_arity),
                        call_arg_types.as_deref(),
                    );
                    if !candidates.is_empty() {
                        return candidates_outcome(candidates);
                    }
                }
            }
            if cpp_unresolved_include_boundary(ctx.analyzer, ctx.file, text) {
                return boundary(format!(
                    "`{text}` appears to cross a C++ include boundary not indexed in this workspace"
                ));
            }
            no_definition(
                "no_indexed_definition",
                format!("`{text}` did not resolve to an indexed C++ callable"),
            )
        }
        "identifier" => {
            let name = cpp_node_text(function, ctx.source);
            if name.is_empty() {
                return no_definition("no_function_name", "C++ call name is blank");
            }
            let bindings = cpp_bindings_before(
                ctx.analyzer,
                ctx.support,
                ctx.visibility,
                ctx.file,
                ctx.source,
                ctx.root,
                function.start_byte(),
            );
            if bindings.is_shadowed(name) {
                return no_definition(
                    "local_variable_reference",
                    format!("`{name}` is a local C++ value"),
                );
            }
            let mut candidates = cpp_visible_name_candidates(
                ctx.analyzer,
                ctx.visibility,
                ctx.file,
                ctx.support,
                name,
                Some(CppTargetKind::FreeFunction),
                None,
            );
            if !candidates.is_empty() {
                candidates = cpp_filter_candidates_by_call(
                    candidates,
                    Some(call_arity),
                    call_arg_types.as_deref(),
                    ctx.analyzer,
                    ctx.visibility,
                    ctx.file,
                );
                return candidates_outcome(candidates);
            }
            if let Some(owner) =
                cpp_enclosing_class(ctx.analyzer, ctx.file, ctx.source, function.start_byte())
            {
                let member_candidates = cpp_member_candidates(
                    ctx,
                    vec![owner],
                    name,
                    Some(call_arity),
                    call_arg_types.as_deref(),
                );
                if !member_candidates.is_empty() {
                    return candidates_outcome(member_candidates);
                }
            }
            no_definition(
                "no_indexed_definition",
                format!("`{name}` did not resolve to an indexed C++ callable"),
            )
        }
        _ => no_definition(
            "unsupported_cpp_reference_shape",
            format!(
                "C++ `{}` call targets are not resolved by get_definition yet",
                function.kind()
            ),
        ),
    }
}

fn resolve_cpp_field(
    ctx: CppLookupCtx<'_, '_>,
    field: Node<'_>,
    arity: Option<usize>,
    arg_types: Option<&[Option<CppType>]>,
) -> DefinitionLookupOutcome {
    let Some(name_node) = field.child_by_field_name("field") else {
        return no_definition("no_member_name", "C++ field expression has no member name");
    };
    let member = cpp_node_text(name_node, ctx.source);
    let Some(receiver) = field
        .child_by_field_name("argument")
        .or_else(|| field.named_child(0))
    else {
        return no_definition("no_member_receiver", "C++ field expression has no receiver");
    };
    let owners = cpp_field_receiver_type_units(
        ctx.analyzer,
        ctx.support,
        ctx.visibility,
        ctx.file,
        ctx.source,
        ctx.root,
        field,
        receiver,
    );
    let candidates = cpp_member_candidates(ctx, owners, member, arity, arg_types);
    if candidates.is_empty() {
        no_definition(
            "unsupported_cpp_receiver",
            format!("receiver for C++ member `{member}` is not resolved"),
        )
    } else {
        candidates_outcome(candidates)
    }
}

fn cpp_visible_name_candidates(
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    support: &DefinitionLookupIndex,
    raw_name: &str,
    kind: Option<CppTargetKind>,
    lexical_namespace: Option<&str>,
) -> Vec<CodeUnit> {
    let normalized = raw_name.trim().trim_start_matches("::");
    let namespace_relative = lexical_namespace
        .filter(|namespace| !namespace.is_empty() && normalized.contains("::"))
        .map(|namespace| format!("{namespace}::{normalized}"));
    let mut candidates = Vec::new();
    for unit in visibility.visible_units(file) {
        if let Some(kind) = kind
            && !cpp_unit_matches_kind(analyzer, support, unit, kind)
        {
            continue;
        }
        let cpp_name = cpp_name_for(unit);
        if cpp_name == normalized
            || namespace_relative
                .as_deref()
                .is_some_and(|relative| cpp_name == relative)
            || (!normalized.contains("::") && unit.identifier() == normalized)
        {
            let indexed = support.fqn(&unit.fq_name());
            if indexed.is_empty() {
                candidates.push(unit.clone());
            } else {
                candidates.extend(indexed);
            }
        }
    }
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn cpp_unit_matches_kind(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    unit: &CodeUnit,
    kind: CppTargetKind,
) -> bool {
    match kind {
        CppTargetKind::FreeFunction => unit.is_function() && !cpp_parent_is_class(support, unit),
        CppTargetKind::Type => unit.is_class() || cpp_unit_is_type_alias(analyzer, unit),
        CppTargetKind::GlobalField => {
            unit.is_field() && cpp_is_unqualified_field(analyzer, support, unit)
        }
        CppTargetKind::MemberField => unit.is_field(),
        CppTargetKind::Constructor | CppTargetKind::Method => true,
    }
}

fn cpp_qualified_identifier_is_declaration_name(node: Node<'_>) -> bool {
    node.kind() == "qualified_identifier"
        && node.parent().is_some_and(|parent| {
            matches!(
                parent.kind(),
                "function_declarator" | "pointer_declarator" | "reference_declarator"
            ) && parent.child_by_field_name("declarator") == Some(node)
        })
}

fn cpp_parent_is_class(support: &DefinitionLookupIndex, unit: &CodeUnit) -> bool {
    let fqn = unit.fq_name();
    let Some((parent_fqn, _)) = fqn.rsplit_once('.') else {
        return false;
    };
    support
        .fqn(parent_fqn)
        .into_iter()
        .any(|parent| parent.is_class())
}

fn cpp_is_unqualified_field(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    unit: &CodeUnit,
) -> bool {
    if !unit.short_name().contains('.') {
        return true;
    }
    let fqn = unit.fq_name();
    let Some((parent_fqn, _)) = fqn.rsplit_once('.') else {
        return false;
    };
    support.fqn(parent_fqn).into_iter().any(|parent| {
        parent
            .signature()
            .is_some_and(|signature| signature.trim_start().starts_with("enum "))
            || analyzer
                .signatures(&parent)
                .iter()
                .any(|signature| signature.trim_start().starts_with("enum "))
    })
}

fn cpp_unit_is_type_alias(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> bool {
    analyzer
        .type_alias_provider()
        .is_some_and(|provider| provider.is_type_alias(unit))
        || unit.signature().is_some_and(cpp_signature_is_type_alias)
}

fn cpp_signature_is_type_alias(signature: &str) -> bool {
    let signature = signature.trim_start();
    signature.starts_with("typedef ")
        || signature.starts_with("using ") && signature.contains('=')
        || signature.starts_with("template ")
            && signature.contains(" using ")
            && signature.contains('=')
}

fn cpp_member_candidates(
    ctx: CppLookupCtx<'_, '_>,
    owners: Vec<CodeUnit>,
    member: &str,
    arity: Option<usize>,
    arg_types: Option<&[Option<CppType>]>,
) -> Vec<CodeUnit> {
    let mut candidates = cpp_direct_member_candidates(ctx.support, &owners, member);
    if candidates.is_empty() {
        let mut seen = HashSet::default();
        candidates = cpp_inherited_member_candidates(ctx, &owners, member, &mut seen);
    }
    candidates = cpp_filter_candidates_by_call(
        candidates,
        arity,
        arg_types,
        ctx.analyzer,
        ctx.visibility,
        ctx.file,
    );
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn cpp_direct_member_candidates(
    support: &DefinitionLookupIndex,
    owners: &[CodeUnit],
    member: &str,
) -> Vec<CodeUnit> {
    let mut candidates = Vec::new();
    for owner in owners {
        candidates.extend(support.fqn(&format!("{}.{}", owner.fq_name(), member)));
    }
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn cpp_inherited_member_candidates(
    ctx: CppLookupCtx<'_, '_>,
    owners: &[CodeUnit],
    member: &str,
    seen: &mut HashSet<String>,
) -> Vec<CodeUnit> {
    let mut bases = Vec::new();
    for owner in owners {
        for base in cpp_direct_base_types(ctx.analyzer, ctx.visibility, ctx.file, owner) {
            if seen.insert(base.fq_name()) {
                bases.push(base);
            }
        }
    }
    if bases.is_empty() {
        return Vec::new();
    }
    let direct = cpp_direct_member_candidates(ctx.support, &bases, member);
    if !direct.is_empty() {
        return direct;
    }
    let mut inherited = cpp_inherited_member_candidates(ctx, &bases, member, seen);
    sort_units(&mut inherited);
    inherited.dedup();
    inherited
}

fn cpp_filter_candidates_by_call(
    candidates: Vec<CodeUnit>,
    arity: Option<usize>,
    arg_types: Option<&[Option<CppType>]>,
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
) -> Vec<CodeUnit> {
    let arity_filtered = cpp_filter_candidates_by_arity(candidates, arity);
    let Some(arg_types) = arg_types else {
        return arity_filtered;
    };
    if arg_types.iter().any(Option::is_none) {
        return arity_filtered;
    }
    let filtered: Vec<_> = arity_filtered
        .iter()
        .filter(|unit| cpp_candidate_params_match_args(unit, arg_types, analyzer, visibility, file))
        .cloned()
        .collect();
    if filtered.is_empty() {
        arity_filtered
    } else {
        filtered
    }
}

fn cpp_filter_candidates_by_arity(
    candidates: Vec<CodeUnit>,
    arity: Option<usize>,
) -> Vec<CodeUnit> {
    let Some(expected) = arity else {
        return candidates;
    };
    let filtered: Vec<_> = candidates
        .iter()
        .filter(|unit| {
            unit.is_function()
                && unit
                    .signature()
                    .is_some_and(|signature| cpp_signature_arity(Some(signature)) == expected)
        })
        .cloned()
        .collect();
    if filtered.is_empty() {
        candidates
    } else {
        filtered
    }
}

fn cpp_candidate_params_match_args(
    candidate: &CodeUnit,
    arg_types: &[Option<CppType>],
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
) -> bool {
    let Some(param_types) = candidate.signature().and_then(cpp_signature_param_types) else {
        return false;
    };
    param_types.len() == arg_types.len()
        && param_types
            .iter()
            .zip(arg_types.iter())
            .all(|(param_type, arg_type)| {
                let Some(arg_type) = arg_type else {
                    return false;
                };
                if cpp_type_text_pointer_depth(param_type) != arg_type.indirection {
                    return false;
                }
                let Some(param_unit) = visibility.resolve_type(file, param_type) else {
                    return false;
                };
                cpp_type_assignable_to(
                    analyzer,
                    visibility,
                    file,
                    &arg_type.unit,
                    &param_unit,
                    &mut HashSet::default(),
                )
            })
}

fn cpp_signature_param_types(signature: &str) -> Option<Vec<String>> {
    let inner = signature
        .find('(')
        .and_then(|open| {
            signature[open + 1..]
                .find(')')
                .map(|close| &signature[open + 1..open + 1 + close])
        })
        .unwrap_or(signature)
        .trim();
    if inner.is_empty() || inner == "void" {
        return Some(Vec::new());
    }
    Some(
        cpp_split_top_level_commas(inner)
            .map(cpp_parameter_type_text)
            .collect(),
    )
}

fn cpp_parameter_type_text(parameter: &str) -> String {
    let mut text = parameter
        .split('=')
        .next()
        .unwrap_or(parameter)
        .trim()
        .trim_end_matches(';')
        .trim();
    // Pointer depth must be read from the raw text: the type normalizer
    // (`normalize_cpp_type_text`) deliberately strips `*`/`&` to get the bare type
    // name, so we capture the depth first and re-append it after normalizing.
    let pointer_depth = cpp_type_text_pointer_depth(text);
    if let Some((before, last)) = text.rsplit_once(char::is_whitespace)
        && cpp_parameter_name_token(last)
    {
        text = before.trim();
    }
    format!(
        "{}{}",
        normalize_cpp_type_text(text),
        "*".repeat(pointer_depth as usize)
    )
}

fn cpp_parameter_name_token(token: &str) -> bool {
    let token = token.trim_start_matches('*').trim_start_matches('&').trim();
    token
        .chars()
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_lowercase())
        && token
            .chars()
            .all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn cpp_type_assignable_to(
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    arg_type: &CodeUnit,
    param_type: &CodeUnit,
    seen: &mut HashSet<String>,
) -> bool {
    if arg_type.fq_name() == param_type.fq_name() {
        return true;
    }
    if !seen.insert(arg_type.fq_name()) {
        return false;
    }
    cpp_direct_base_types(analyzer, visibility, file, arg_type)
        .into_iter()
        .any(|base| {
            base.fq_name() == param_type.fq_name()
                || cpp_type_assignable_to(analyzer, visibility, file, &base, param_type, seen)
        })
}

fn cpp_direct_base_types(
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    unit: &CodeUnit,
) -> Vec<CodeUnit> {
    let signature = unit
        .signature()
        .map(str::to_string)
        .or_else(|| analyzer.get_source(unit, false));
    let Some(signature) = signature else {
        return Vec::new();
    };
    let Some((_, bases)) = signature.split_once(':') else {
        return Vec::new();
    };
    let bases = bases.split('{').next().unwrap_or(bases);
    cpp_split_top_level_commas(bases)
        .filter_map(|base| visibility.resolve_type(file, &cpp_base_type_text(base)))
        .collect()
}

fn cpp_base_type_text(base: &str) -> String {
    let filtered = base
        .split_whitespace()
        .filter(|token| !matches!(*token, "public" | "private" | "protected" | "virtual"))
        .collect::<Vec<_>>()
        .join(" ");
    normalize_cpp_type_text(&filtered)
}

/// A C++ value type paired with its pointer indirection depth: 0 for a value or
/// reference, 1 for `T*`, 2 for `T**`, and so on. References bind from values, so
/// they contribute depth 0; only `*` levels must agree between an argument and a
/// parameter for overload matching.
#[derive(Clone, PartialEq, Eq, Hash)]
struct CppType {
    unit: CodeUnit,
    indirection: i32,
    alias_unit: Option<CodeUnit>,
}

/// Top-level pointer depth declared by `text` (the number of `*` outside any
/// template/array/parameter brackets). `&` is ignored: a reference parameter
/// binds from a value argument.
fn cpp_type_text_pointer_depth(text: &str) -> i32 {
    let mut depth = 0i32;
    let mut bracket = 0i32;
    for ch in text.chars() {
        match ch {
            '<' | '(' | '[' => bracket += 1,
            '>' | ')' | ']' => bracket -= 1,
            '*' if bracket <= 0 => depth += 1,
            _ => {}
        }
    }
    depth
}

/// Pointer depth contributed by a declarator: one per `pointer_declarator`
/// wrapping the name. `reference_declarator` contributes nothing.
fn cpp_declarator_pointer_depth(declarator: Node<'_>) -> i32 {
    let mut depth = 0;
    let mut current = declarator;
    loop {
        if current.kind() == "pointer_declarator" {
            depth += 1;
        }
        match current.child_by_field_name("declarator") {
            Some(inner) => current = inner,
            None => return depth,
        }
    }
}

/// Indirection change of a `pointer_expression`: `&x` adds a pointer level, `*x`
/// removes one. `None` for any other unary operator sharing this node kind.
fn cpp_pointer_expression_delta(node: Node<'_>) -> Option<i32> {
    match node.child_by_field_name("operator")?.kind() {
        "&" => Some(1),
        "*" => Some(-1),
        _ => None,
    }
}

fn cpp_call_argument_types(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    call: Node<'_>,
) -> Option<Vec<Option<CppType>>> {
    let args = call
        .child_by_field_name("arguments")
        .or_else(|| call.child_by_field_name("parameters"))
        .or_else(|| call.child_by_field_name("value"))?;
    let mut cursor = args.walk();
    Some(
        args.named_children(&mut cursor)
            .map(|arg| cpp_expression_type(analyzer, support, visibility, file, source, root, arg))
            .collect(),
    )
}

fn cpp_expression_type(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    node: Node<'_>,
) -> Option<CppType> {
    match node.kind() {
        "identifier" => {
            let name = cpp_node_text(node, source);
            let bindings = cpp_bindings_before(
                analyzer,
                support,
                visibility,
                file,
                source,
                root,
                node.start_byte(),
            );
            first_precise(&bindings, name)
        }
        "field_expression" => {
            cpp_field_expression_type(analyzer, support, visibility, file, source, root, node)
        }
        "new_expression" | "call_expression" => {
            cpp_infer_type_from_value(analyzer, support, visibility, file, source, node)
        }
        "parenthesized_expression" => node
            .child_by_field_name("argument")
            .or_else(|| node.named_child(0))
            .and_then(|inner| {
                cpp_expression_type(analyzer, support, visibility, file, source, root, inner)
            }),
        "pointer_expression" => {
            let delta = cpp_pointer_expression_delta(node)?;
            let inner = node
                .child_by_field_name("argument")
                .or_else(|| node.named_child(0))?;
            let mut inner_type =
                cpp_expression_type(analyzer, support, visibility, file, source, root, inner)?;
            inner_type.indirection += delta;
            Some(inner_type)
        }
        _ => None,
    }
}

fn cpp_field_expression_type(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    field: Node<'_>,
) -> Option<CppType> {
    let member = field
        .child_by_field_name("field")
        .map(|field| cpp_node_text(field, source))?;
    let receiver = field
        .child_by_field_name("argument")
        .or_else(|| field.named_child(0))?;
    let owners = cpp_field_receiver_type_units(
        analyzer, support, visibility, file, source, root, field, receiver,
    );
    let candidates = cpp_member_candidates(
        CppLookupCtx {
            analyzer,
            support,
            file,
            visibility,
            source,
            root,
        },
        owners,
        member,
        None,
        None,
    );
    candidates
        .into_iter()
        .filter(|unit| unit.is_field())
        .find_map(|unit| cpp_field_declared_type(analyzer, visibility, file, &unit))
}

fn cpp_field_declared_type(
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    field: &CodeUnit,
) -> Option<CppType> {
    let declaration_text = field
        .signature()
        .map(str::to_string)
        .or_else(|| analyzer.get_source(field, false))?;
    let declaration = declaration_text
        .split('=')
        .next()
        .unwrap_or(&declaration_text)
        .trim()
        .trim_end_matches(';')
        .trim();
    let name_at = declaration.rfind(field.identifier())?;
    let type_text = declaration[..name_at].trim();
    if type_text.is_empty() {
        return None;
    }
    let indirection = cpp_type_text_pointer_depth(type_text);
    visibility
        .resolve_type(file, type_text)
        .map(|unit| CppType {
            unit,
            indirection,
            alias_unit: None,
        })
}

fn cpp_receiver_type_units(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    receiver: Node<'_>,
    unwrap_template_alias: bool,
) -> Vec<CodeUnit> {
    match receiver.kind() {
        "identifier" => {
            let name = cpp_node_text(receiver, source);
            let bindings = cpp_bindings_before(
                analyzer,
                support,
                visibility,
                file,
                source,
                root,
                receiver.start_byte(),
            );
            if let Some(cpp_type) = first_precise(&bindings, name) {
                return vec![cpp_receiver_unit_for_access(
                    analyzer,
                    visibility,
                    file,
                    cpp_type,
                    unwrap_template_alias,
                )];
            }
            if bindings.is_shadowed(name) {
                Vec::new()
            } else {
                visibility.resolve_type(file, name).into_iter().collect()
            }
        }
        "this" => cpp_enclosing_class(analyzer, file, source, receiver.start_byte())
            .into_iter()
            .collect(),
        "field_expression" => {
            cpp_field_expression_type(analyzer, support, visibility, file, source, root, receiver)
                .map(|cpp_type| cpp_type.unit)
                .into_iter()
                .collect()
        }
        "parenthesized_expression" | "pointer_expression" => receiver
            .child_by_field_name("argument")
            .or_else(|| receiver.named_child(0))
            .map(|inner| {
                cpp_receiver_type_units(
                    analyzer,
                    support,
                    visibility,
                    file,
                    source,
                    root,
                    inner,
                    unwrap_template_alias,
                )
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

#[allow(clippy::too_many_arguments)]
fn cpp_field_receiver_type_units(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    field: Node<'_>,
    receiver: Node<'_>,
) -> Vec<CodeUnit> {
    cpp_receiver_type_units(
        analyzer,
        support,
        visibility,
        file,
        source,
        root,
        receiver,
        cpp_field_expression_uses_arrow(field, source),
    )
}

fn cpp_receiver_unit_for_access(
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    cpp_type: CppType,
    unwrap_template_alias: bool,
) -> CodeUnit {
    if unwrap_template_alias
        && let Some(alias) = cpp_type.alias_unit.as_ref()
        && let Some(target) =
            cpp_alias_template_first_argument_target_unit(analyzer, visibility, file, alias)
    {
        return target;
    }
    cpp_type.unit
}

fn cpp_field_expression_uses_arrow(field: Node<'_>, source: &str) -> bool {
    let Some(receiver) = field
        .child_by_field_name("argument")
        .or_else(|| field.named_child(0))
    else {
        return false;
    };
    let Some(name) = field.child_by_field_name("field") else {
        return false;
    };
    source
        .get(receiver.end_byte()..name.start_byte())
        .is_some_and(|between| between.contains("->"))
}

fn cpp_enclosing_class(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    byte: usize,
) -> Option<CodeUnit> {
    if let Some(fqn) = ClassRangeIndex::build(analyzer, file).enclosing(byte) {
        return analyzer.definitions(fqn).next().cloned();
    }

    let line_starts = compute_line_starts(source);
    let line = find_line_index_for_offset(&line_starts, byte) + 1;
    let range = Range {
        start_byte: byte,
        end_byte: byte.saturating_add(1),
        start_line: line,
        end_line: line,
    };
    let enclosing = analyzer.enclosing_code_unit(file, &range)?;
    let enclosing_fqn = enclosing.fq_name();
    let owner_fqn = enclosing_fqn.rsplit_once('.')?.0;
    analyzer
        .definitions(owner_fqn)
        .find(|unit| unit.is_class())
        .cloned()
}

const CPP_SCOPE_NODES: &[&str] = &[
    "compound_statement",
    "function_definition",
    "lambda_expression",
    "for_range_loop",
    "for_statement",
    "while_statement",
    "if_statement",
];

fn cpp_bindings_before(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    cutoff_start: usize,
) -> LocalInferenceEngine<CppType> {
    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    cpp_seed_active_path(
        analyzer,
        support,
        visibility,
        file,
        source,
        root,
        cutoff_start,
        &mut bindings,
    );
    bindings
}

fn cpp_local_bindings_before(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    _root: Node<'_>,
    node: Node<'_>,
    cutoff_start: usize,
) -> LocalInferenceEngine<CppType> {
    let Some(local_root) = cpp_enclosing_local_scope(node) else {
        return LocalInferenceEngine::new(LocalInferenceConfig::default());
    };
    cpp_bindings_before(
        analyzer,
        support,
        visibility,
        file,
        source,
        local_root,
        cutoff_start,
    )
}

fn cpp_enclosing_local_scope(mut node: Node<'_>) -> Option<Node<'_>> {
    let mut fallback = None;
    while let Some(parent) = node.parent() {
        if matches!(parent.kind(), "function_definition" | "lambda_expression") {
            return Some(parent);
        }
        if fallback.is_none() && parent.kind() == "compound_statement" {
            fallback = Some(parent);
        }
        node = parent;
    }
    fallback
}

fn cpp_seed_active_path(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    cutoff_start: usize,
    bindings: &mut LocalInferenceEngine<CppType>,
) {
    if node.start_byte() >= cutoff_start {
        return;
    }
    let enters_scope = CPP_SCOPE_NODES.contains(&node.kind());
    if enters_scope && !(node.start_byte() <= cutoff_start && cutoff_start < node.end_byte()) {
        return;
    }
    if enters_scope {
        bindings.enter_scope();
    }
    match node.kind() {
        "parameter_declaration" | "optional_parameter_declaration"
            if node.end_byte() <= cutoff_start =>
        {
            cpp_seed_typed_binding(analyzer, support, visibility, file, source, node, bindings)
        }
        "for_range_loop" if node.start_byte() < cutoff_start => cpp_seed_for_range_binding(
            analyzer,
            support,
            visibility,
            file,
            source,
            node,
            cutoff_start,
            bindings,
        ),
        "declaration" | "field_declaration" if node.start_byte() < cutoff_start => {
            cpp_seed_variable_declaration(
                analyzer,
                support,
                visibility,
                file,
                source,
                node,
                cutoff_start,
                bindings,
            )
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.start_byte() >= cutoff_start {
            break;
        }
        cpp_seed_active_path(
            analyzer,
            support,
            visibility,
            file,
            source,
            child,
            cutoff_start,
            bindings,
        );
    }
}

fn cpp_seed_typed_binding(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    bindings: &mut LocalInferenceEngine<CppType>,
) {
    let Some(declarator) = node.child_by_field_name("declarator") else {
        return;
    };
    let Some(name) = extract_variable_name(declarator, source) else {
        return;
    };
    let type_text = node
        .child_by_field_name("type")
        .or_else(|| cpp_first_type_child(node))
        .map(|type_node| normalize_cpp_type_text(cpp_node_text(type_node, source)));
    cpp_seed_binding(
        analyzer,
        support,
        visibility,
        file,
        source,
        &name,
        type_text.as_deref(),
        cpp_declarator_pointer_depth(declarator),
        None,
        bindings,
    );
}

fn cpp_seed_for_range_binding(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    cutoff_start: usize,
    bindings: &mut LocalInferenceEngine<CppType>,
) {
    if node
        .child_by_field_name("body")
        .is_none_or(|body| body.start_byte() > cutoff_start)
    {
        return;
    }
    let Some(declarator) = node.child_by_field_name("declarator") else {
        return;
    };
    let Some(name) = extract_variable_name(declarator, source) else {
        return;
    };
    let type_text = node
        .child_by_field_name("type")
        .or_else(|| cpp_first_type_child(node))
        .map(|type_node| normalize_cpp_type_text(cpp_node_text(type_node, source)));
    cpp_seed_binding(
        analyzer,
        support,
        visibility,
        file,
        source,
        &name,
        type_text.as_deref(),
        cpp_declarator_pointer_depth(declarator),
        None,
        bindings,
    );
}

fn cpp_seed_variable_declaration(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    cutoff_start: usize,
    bindings: &mut LocalInferenceEngine<CppType>,
) {
    let type_text = node
        .child_by_field_name("type")
        .or_else(|| cpp_first_type_child(node))
        .map(|type_node| normalize_cpp_type_text(cpp_node_text(type_node, source)));
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        let declarator = if child.kind() == "init_declarator" {
            child.child_by_field_name("declarator")
        } else if cpp_is_declarator_node(child) {
            Some(child)
        } else {
            None
        };
        let Some(declarator) = declarator else {
            continue;
        };
        if declarator.start_byte() >= cutoff_start {
            continue;
        }
        if declarator.kind() == "function_declarator"
            && !cpp_constructor_style_local_declaration(
                visibility,
                file,
                source,
                declarator,
                type_text.as_deref(),
                bindings,
            )
        {
            continue;
        }
        if let Some(name) = extract_variable_name(declarator, source) {
            let value = child
                .child_by_field_name("value")
                .filter(|value| value.end_byte() <= cutoff_start);
            cpp_seed_binding(
                analyzer,
                support,
                visibility,
                file,
                source,
                &name,
                type_text.as_deref(),
                cpp_declarator_pointer_depth(declarator),
                value,
                bindings,
            );
        }
    }
}

fn cpp_constructor_style_local_declaration(
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    declarator: Node<'_>,
    type_text: Option<&str>,
    bindings: &LocalInferenceEngine<CppType>,
) -> bool {
    let Some(parameters) = declarator.child_by_field_name("parameters") else {
        return false;
    };
    if parameters.named_child_count() == 0 {
        return false;
    }
    if extract_variable_name(declarator, source).is_none() {
        return false;
    }
    if !type_text
        .and_then(|text| visibility.resolve_type(file, text))
        .is_some_and(|unit| unit.is_class())
    {
        return false;
    }
    cpp_constructor_arguments_look_like_expressions(visibility, file, source, parameters, bindings)
}

fn cpp_constructor_arguments_look_like_expressions(
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    parameters: Node<'_>,
    bindings: &LocalInferenceEngine<CppType>,
) -> bool {
    let text = cpp_node_text(parameters, source);
    let inner = text.trim().trim_start_matches('(').trim_end_matches(')');
    cpp_split_top_level_commas(inner).any(|argument| {
        let argument = argument.trim();
        !argument.is_empty()
            && !cpp_argument_looks_like_parameter_declaration(visibility, file, argument, bindings)
    })
}

fn cpp_argument_looks_like_parameter_declaration(
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    argument: &str,
    bindings: &LocalInferenceEngine<CppType>,
) -> bool {
    let without_default = argument.split('=').next().unwrap_or(argument).trim();
    if without_default.is_empty() {
        return false;
    }
    if is_cpp_local_symbol_expression(without_default, bindings) {
        return false;
    }
    if cpp_builtin_type_text(without_default) {
        return true;
    }
    visibility
        .resolve_type(file, &cpp_parameter_type_text(without_default))
        .is_some()
}

fn is_cpp_local_symbol_expression(
    argument: &str,
    bindings: &LocalInferenceEngine<CppType>,
) -> bool {
    argument
        .chars()
        .all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        && !bindings.resolve_symbol(argument).is_unknown()
}

fn cpp_builtin_type_text(text: &str) -> bool {
    // Builtin-ness is a property of the base type, independent of pointer depth,
    // so drop the trailing `*` markers that `cpp_parameter_type_text` appends.
    let normalized = cpp_parameter_type_text(text);
    let normalized = normalized.trim_end_matches('*');
    let tokens: Vec<_> = normalized.split_whitespace().collect();
    !tokens.is_empty()
        && tokens.iter().all(|token| {
            matches!(
                *token,
                "auto"
                    | "bool"
                    | "char"
                    | "char8_t"
                    | "char16_t"
                    | "char32_t"
                    | "const"
                    | "double"
                    | "float"
                    | "int"
                    | "long"
                    | "short"
                    | "signed"
                    | "size_t"
                    | "unsigned"
                    | "void"
                    | "volatile"
                    | "wchar_t"
            )
        })
}

#[allow(clippy::too_many_arguments)]
fn cpp_seed_binding(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    name: &str,
    type_text: Option<&str>,
    declarator_depth: i32,
    value: Option<Node<'_>>,
    bindings: &mut LocalInferenceEngine<CppType>,
) {
    if name.is_empty() {
        return;
    }
    let resolved = type_text
        .filter(|text| *text != "auto")
        .and_then(|text| cpp_resolve_type_unit(analyzer, visibility, file, text))
        .map(|unit| CppType {
            unit,
            indirection: 0,
            alias_unit: type_text
                .and_then(|text| cpp_resolve_type_alias_unit(analyzer, visibility, file, text)),
        })
        .or_else(|| {
            value.and_then(|value| {
                cpp_infer_type_from_value(analyzer, support, visibility, file, source, value)
            })
        });
    match resolved {
        Some(mut cpp_type) => {
            // The declarator (`T* p`, `T** pp`) adds to whatever the type spelling
            // or inferred value contributed.
            cpp_type.indirection += declarator_depth;
            bindings.seed_symbol(name.to_string(), cpp_type);
        }
        None => bindings.declare_shadow(name.to_string()),
    }
}

fn cpp_resolve_type_unit(
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    type_text: &str,
) -> Option<CodeUnit> {
    let mut seen = HashSet::default();
    cpp_resolve_type_unit_inner(analyzer, visibility, file, type_text, &mut seen)
}

fn cpp_resolve_type_alias_unit(
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    type_text: &str,
) -> Option<CodeUnit> {
    let name = normalize_cpp_type_text(type_text);
    visibility.visible_units(file).find_map(|unit| {
        (cpp_unit_is_type_alias(analyzer, unit) && cpp_type_unit_matches_name(unit, &name))
            .then(|| unit.clone())
    })
}

fn cpp_resolve_type_unit_inner(
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    type_text: &str,
    seen: &mut HashSet<String>,
) -> Option<CodeUnit> {
    let name = normalize_cpp_type_text(type_text);
    if !seen.insert(name.clone()) {
        return None;
    }
    let mut targets = visibility
        .visible_units(file)
        .filter(|unit| {
            (unit.is_class() || cpp_unit_is_type_alias(analyzer, unit))
                && cpp_type_unit_matches_name(unit, &name)
        })
        .filter_map(|unit| {
            cpp_alias_target_unit(analyzer, visibility, file, unit, seen)
                .or_else(|| (!cpp_unit_is_type_alias(analyzer, unit)).then(|| unit.clone()))
        })
        .collect::<Vec<_>>();
    if targets.is_empty()
        && let Some(unit) = visibility.resolve_type(file, type_text)
    {
        targets
            .push(cpp_alias_target_unit(analyzer, visibility, file, &unit, seen).unwrap_or(unit));
    }
    cpp_choose_canonical_type(analyzer, targets)
}

fn cpp_type_unit_matches_name(unit: &CodeUnit, name: &str) -> bool {
    if name.contains("::") {
        cpp_name_for(unit) == name
    } else {
        unit.identifier() == name
    }
}

fn cpp_choose_canonical_type(
    analyzer: &dyn IAnalyzer,
    mut candidates: Vec<CodeUnit>,
) -> Option<CodeUnit> {
    sort_units(&mut candidates);
    candidates.dedup();
    let first = candidates.first()?.clone();
    let cpp_name = cpp_name_for(&first);
    if !candidates
        .iter()
        .all(|candidate| cpp_name_for(candidate) == cpp_name)
    {
        return (candidates.len() == 1).then_some(first);
    }
    candidates
        .iter()
        .find(|candidate| cpp_type_has_definition_body(analyzer, candidate))
        .cloned()
        .or(Some(first))
}

fn cpp_type_has_definition_body(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> bool {
    unit.signature()
        .is_some_and(|signature| signature.contains('{') || signature.contains(':'))
        || analyzer
            .signatures(unit)
            .iter()
            .any(|signature| signature.contains('{') || signature.contains(':'))
        || analyzer
            .get_source(unit, false)
            .is_some_and(|source| source.contains('{') || source.contains(':'))
}

fn cpp_alias_target_unit(
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    unit: &CodeUnit,
    seen: &mut HashSet<String>,
) -> Option<CodeUnit> {
    if !cpp_unit_is_type_alias(analyzer, unit) {
        return None;
    }
    cpp_alias_target_texts(analyzer, unit)
        .find_map(|rhs| cpp_resolve_type_unit_inner(analyzer, visibility, file, &rhs, seen))
}

fn cpp_alias_template_first_argument_target_unit(
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    unit: &CodeUnit,
) -> Option<CodeUnit> {
    let mut seen = HashSet::default();
    cpp_alias_target_texts(analyzer, unit).find_map(|rhs| {
        let target = cpp_template_first_argument(&rhs)?;
        cpp_resolve_type_unit_inner(analyzer, visibility, file, target, &mut seen)
    })
}

fn cpp_alias_target_texts<'a>(
    analyzer: &'a dyn IAnalyzer,
    unit: &'a CodeUnit,
) -> impl Iterator<Item = String> + 'a {
    unit.signature()
        .map(str::to_string)
        .into_iter()
        .chain(analyzer.signatures(unit).iter().cloned())
        .chain(analyzer.get_source(unit, false))
        .filter_map(|signature| cpp_alias_target_text(&signature))
}

fn cpp_alias_target_text(signature: &str) -> Option<String> {
    let signature = signature.trim();
    let rhs = if let Some((_, rhs)) = signature.split_once('=') {
        rhs
    } else if let Some(rest) = signature.strip_prefix("typedef ") {
        rest.rsplit_once(char::is_whitespace)?.0
    } else {
        return None;
    };
    Some(rhs.trim().trim_end_matches(';').trim().to_string())
}

fn cpp_template_first_argument(type_text: &str) -> Option<&str> {
    let open = type_text.find('<')?;
    let close = type_text.rfind('>')?;
    (close > open).then_some(type_text[open + 1..close].split(',').next()?.trim())
}

fn cpp_infer_type_from_value(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
) -> Option<CppType> {
    match node.kind() {
        "new_expression" => {
            let text = cpp_node_text(node, source).trim();
            let rest = text.strip_prefix("new ").unwrap_or(text);
            visibility
                .resolve_type(file, rest.split(['(', '{']).next().unwrap_or(rest))
                // `new T` yields a `T*`.
                .map(|unit| CppType {
                    unit,
                    indirection: 1,
                    alias_unit: None,
                })
        }
        "call_expression" => {
            cpp_call_return_type(analyzer, support, visibility, file, source, node).or_else(|| {
                node.child_by_field_name("function")
                    .and_then(|function| {
                        visibility.resolve_type(file, cpp_node_text(function, source))
                    })
                    .map(|unit| CppType {
                        unit,
                        indirection: 0,
                        alias_unit: None,
                    })
            })
        }
        _ => None,
    }
}

fn cpp_call_return_type(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    call: Node<'_>,
) -> Option<CppType> {
    let function = call.child_by_field_name("function")?;
    let arity = cpp_call_arity(call);
    let candidates = match function.kind() {
        "qualified_identifier" => {
            let scope = function.child_by_field_name("scope")?;
            let name = function.child_by_field_name("name")?;
            let owner = visibility.resolve_type(file, cpp_node_text(scope, source))?;
            cpp_filter_candidates_by_arity(
                cpp_direct_member_candidates(support, &[owner], cpp_node_text(name, source)),
                Some(arity),
            )
        }
        "identifier" => cpp_filter_candidates_by_arity(
            cpp_visible_name_candidates(
                analyzer,
                visibility,
                file,
                support,
                cpp_node_text(function, source),
                Some(CppTargetKind::FreeFunction),
                None,
            ),
            Some(arity),
        ),
        _ => Vec::new(),
    };
    candidates
        .iter()
        .find_map(|candidate| cpp_function_return_type(analyzer, visibility, file, candidate))
}

fn cpp_function_return_type(
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    function: &CodeUnit,
) -> Option<CppType> {
    let signature = function
        .signature()
        .filter(|signature| signature.contains(function.identifier()))
        .map(str::to_string)
        .or_else(|| analyzer.signatures(function).first().cloned())
        .or_else(|| analyzer.get_source(function, false))?;
    let name_at = signature.find(function.identifier())?;
    let type_text = signature[..name_at]
        .split_whitespace()
        .filter(|token| {
            !matches!(
                *token,
                "static" | "virtual" | "inline" | "constexpr" | "explicit" | "friend"
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    let type_text = type_text.trim();
    if type_text.is_empty() {
        return None;
    }
    let indirection = cpp_type_text_pointer_depth(type_text);
    let type_text = normalize_cpp_type_text(type_text);
    visibility
        .resolve_type(file, &type_text)
        .map(|unit| CppType {
            unit,
            indirection,
            alias_unit: cpp_resolve_type_alias_unit(analyzer, visibility, file, &type_text),
        })
}

fn cpp_unresolved_include_boundary(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    reference: &str,
) -> bool {
    if !reference.contains("::") && !reference.chars().next().is_some_and(char::is_uppercase) {
        return false;
    }
    analyzer.import_statements(file).iter().any(|import| {
        cpp_include_paths(std::slice::from_ref(import))
            .iter()
            .any(|include| resolve_include_targets(analyzer.project(), file, include).is_empty())
    })
}

fn cpp_lexical_namespace(node: Node<'_>, source: &str) -> Option<String> {
    let mut names = Vec::new();
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "namespace_definition"
            && let Some(name) = parent.child_by_field_name("name")
        {
            names.push(cpp_node_text(name, source).trim().to_string());
        }
        current = parent.parent();
    }
    names.reverse();
    (!names.is_empty()).then(|| names.join("::"))
}

fn resolve_scala(
    analyzer: &dyn IAnalyzer,
    context: &mut DefinitionBatchContext<'_>,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    let Some(scala) = resolve_analyzer::<ScalaAnalyzer>(analyzer) else {
        return no_definition(
            "scala_analyzer_unavailable",
            "Scala analyzer is unavailable",
        );
    };
    let Some(tree) = tree else {
        return no_definition("scala_parse_failed", "Scala source could not be parsed");
    };
    let types = context.scala_project_types(scala);
    let support = context.support;
    let resolver = ScalaNameResolver::for_file(scala, file, types.as_ref());
    let root = tree.root_node();
    let Some(node) = smallest_named_node_covering(root, site.focus_start_byte, site.focus_end_byte)
    else {
        return no_definition(
            "no_indexed_definition",
            format!(
                "`{}` did not resolve to an indexed Scala definition",
                site.text
            ),
        );
    };
    if scala_is_declaration_name(node) {
        return no_definition(
            "declaration_or_import_site",
            format!("`{}` is not a Scala reference site", site.text),
        );
    }

    match scala_reference_node(node) {
        Some(ScalaReferenceNode::Type(type_node)) => {
            let ctx = ScalaLookupCtx {
                scala,
                analyzer,
                support,
                file,
                source,
            };
            resolve_scala_type(ctx, &resolver, root, type_node)
        }
        Some(ScalaReferenceNode::Call(call)) => {
            let ctx = ScalaLookupCtx {
                scala,
                analyzer,
                support,
                file,
                source,
            };
            resolve_scala_call(ctx, &resolver, root, call)
        }
        Some(ScalaReferenceNode::Field(field)) => resolve_scala_field(
            ScalaLookupCtx {
                scala,
                analyzer,
                support,
                file,
                source,
            },
            &resolver,
            root,
            field,
        ),
        Some(ScalaReferenceNode::Identifier(identifier)) => {
            let text = scala_node_text(identifier, source).trim();
            if text.is_empty() {
                return no_definition("no_reference_text", "Scala identifier is blank");
            }
            let bindings = scala_bindings_before(&resolver, source, root, identifier.start_byte());
            if bindings.is_shadowed(text) {
                return no_definition(
                    "local_variable_reference",
                    format!("`{text}` is a local Scala value"),
                );
            }
            if let Some(fqn) = resolver.resolve(text) {
                return scala_fqn_outcome(support, &fqn, text);
            }
            if scala_import_boundary_for_name(scala, context.support, file, text) {
                return boundary(format!(
                    "`{text}` appears to cross a Scala import boundary not indexed in this workspace"
                ));
            }
            no_definition(
                "no_indexed_definition",
                format!("`{text}` did not resolve to an indexed Scala definition"),
            )
        }
        None => no_definition(
            "unsupported_scala_reference_shape",
            format!(
                "`{}` is a Scala `{}` reference shape that get_definition does not resolve yet",
                site.text,
                node.kind()
            ),
        ),
    }
}

fn parse_scala_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_scala::LANGUAGE.into())
        .ok()?;
    parser.parse(source, None)
}

enum ScalaReferenceNode<'tree> {
    Type(Node<'tree>),
    Call(Node<'tree>),
    Field(Node<'tree>),
    Identifier(Node<'tree>),
}

fn scala_reference_node(node: Node<'_>) -> Option<ScalaReferenceNode<'_>> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "field_expression"
            && parent.child_by_field_name("field") == Some(current)
        {
            current = parent;
            continue;
        }
        if parent.kind() == "call_expression"
            && parent.child_by_field_name("function") == Some(current)
        {
            current = parent;
            continue;
        }
        break;
    }

    match current.kind() {
        "call_expression" => Some(ScalaReferenceNode::Call(current)),
        "field_expression" => Some(ScalaReferenceNode::Field(current)),
        "type_identifier" | "stable_type_identifier" | "generic_type" => {
            Some(ScalaReferenceNode::Type(current))
        }
        "identifier" | "operator_identifier" => Some(ScalaReferenceNode::Identifier(current)),
        _ => None,
    }
}

fn scala_is_declaration_name(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    parent.child_by_field_name("name") == Some(node)
        && matches!(
            parent.kind(),
            "class_definition"
                | "object_definition"
                | "trait_definition"
                | "enum_definition"
                | "function_definition"
                | "parameter"
                | "val_definition"
                | "var_definition"
        )
}

fn scala_is_type_position(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.child_by_field_name("type") == Some(current) {
            return true;
        }
        if matches!(parent.kind(), "generic_type" | "stable_type_identifier") {
            current = parent;
            continue;
        }
        return false;
    }
    false
}

#[derive(Clone, Copy)]
struct ScalaLookupCtx<'a> {
    scala: &'a ScalaAnalyzer,
    analyzer: &'a dyn IAnalyzer,
    support: &'a DefinitionLookupIndex,
    file: &'a ProjectFile,
    source: &'a str,
}

fn resolve_scala_type(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    node: Node<'_>,
) -> DefinitionLookupOutcome {
    let text = scala_node_text(node, ctx.source).trim();
    if text.is_empty() {
        return no_definition("no_reference_text", "Scala type reference is blank");
    }
    if !scala_is_type_position(node) {
        let bindings = scala_bindings_before(resolver, ctx.source, root, node.start_byte());
        if bindings.is_shadowed(text) {
            return no_definition(
                "local_variable_reference",
                format!("`{text}` is a local Scala value"),
            );
        }
    }
    if let Some(fqn) = resolver.resolve(text) {
        return scala_fqn_outcome(ctx.support, &fqn, text);
    }
    if scala_import_boundary_for_name(ctx.scala, ctx.support, ctx.file, scala_simple_name(text)) {
        return boundary(format!(
            "`{text}` appears to cross a Scala import boundary not indexed in this workspace"
        ));
    }
    no_definition(
        "no_indexed_definition",
        format!("`{text}` did not resolve to an indexed Scala type"),
    )
}

fn resolve_scala_call(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    call: Node<'_>,
) -> DefinitionLookupOutcome {
    let Some(function) = call.child_by_field_name("function") else {
        return no_definition("no_function_name", "Scala call expression has no function");
    };
    match function.kind() {
        "field_expression" => resolve_scala_field(ctx, resolver, root, function),
        "identifier" | "type_identifier" => {
            let name = scala_node_text(function, ctx.source).trim();
            if name.is_empty() {
                return no_definition("no_function_name", "Scala call name is blank");
            }
            let bindings = scala_bindings_before(resolver, ctx.source, root, function.start_byte());
            if bindings.is_shadowed(name) {
                return no_definition(
                    "local_variable_reference",
                    format!("`{name}` is a local Scala value"),
                );
            }
            if function.kind() == "identifier"
                && let Some(owner) =
                    scala_enclosing_class(ctx.analyzer, ctx.file, function.start_byte())
                && owner.identifier() != name
            {
                let mut candidates = scala_member_candidate_units(ctx, &owner.fq_name(), name);
                if candidates.is_empty() {
                    candidates = scala_source_ancestor_member_units(ctx, resolver, function, name);
                }
                if !candidates.is_empty() {
                    return candidates_outcome(candidates);
                }
            }
            if let Some(owner_fqn) = resolver.resolve(name) {
                let apply_candidates = ctx.support.fqn(&format!("{owner_fqn}.apply"));
                if !apply_candidates.is_empty() {
                    return candidates_outcome(apply_candidates);
                }
                return scala_fqn_outcome(ctx.support, &owner_fqn, name);
            }
            if scala_import_boundary_for_name(ctx.scala, ctx.support, ctx.file, name) {
                return boundary(format!(
                    "`{name}` appears to cross a Scala import boundary not indexed in this workspace"
                ));
            }
            no_definition(
                "no_indexed_definition",
                format!("`{name}` did not resolve to an indexed Scala callable"),
            )
        }
        _ => no_definition(
            "unsupported_scala_reference_shape",
            format!(
                "Scala `{}` call targets are not resolved by get_definition yet",
                function.kind()
            ),
        ),
    }
}

fn resolve_scala_field(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    field: Node<'_>,
) -> DefinitionLookupOutcome {
    let Some(field_node) = field.child_by_field_name("field") else {
        return no_definition(
            "no_member_name",
            "Scala field expression has no member name",
        );
    };
    let member = scala_node_text(field_node, ctx.source).trim();
    let Some(receiver) = field.child_by_field_name("value") else {
        return no_definition(
            "no_member_receiver",
            "Scala field expression has no receiver",
        );
    };
    if let Some(owner) = scala_receiver_type_fqn(ctx, resolver, root, receiver, field.start_byte())
    {
        return scala_member_candidates(ctx, &owner, member);
    }
    no_definition(
        "unsupported_scala_receiver",
        format!("receiver for Scala member `{member}` is not resolved"),
    )
}

fn scala_member_candidates(
    ctx: ScalaLookupCtx<'_>,
    owner_fqn: &str,
    member: &str,
) -> DefinitionLookupOutcome {
    let candidates = scala_member_candidate_units(ctx, owner_fqn, member);
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }

    scala_member_not_found(ctx, owner_fqn, member)
}

fn scala_member_candidate_units(
    ctx: ScalaLookupCtx<'_>,
    owner_fqn: &str,
    member: &str,
) -> Vec<CodeUnit> {
    let mut candidates = ctx.support.fqn(&format!("{owner_fqn}.{member}"));
    sort_units(&mut candidates);
    candidates.dedup();
    if !candidates.is_empty() {
        return candidates;
    }

    if let Some(owner) = ctx.analyzer.definitions(owner_fqn).next().cloned()
        && let Some(provider) = ctx.analyzer.type_hierarchy_provider()
    {
        let mut seen = HashSet::default();
        let mut level = provider.get_direct_ancestors(&owner);
        seen.insert(owner);
        while !level.is_empty() {
            let mut level_candidates = Vec::new();
            let mut next_level = Vec::new();
            for ancestor in level {
                if !seen.insert(ancestor.clone()) {
                    continue;
                }
                level_candidates
                    .extend(ctx.support.fqn(&format!("{}.{member}", ancestor.fq_name())));
                next_level.extend(provider.get_direct_ancestors(&ancestor));
            }
            sort_units(&mut level_candidates);
            level_candidates.dedup();
            if !level_candidates.is_empty() {
                return level_candidates;
            }
            level = next_level;
        }
    }

    Vec::new()
}

fn scala_source_ancestor_member_units(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    node: Node<'_>,
    member: &str,
) -> Vec<CodeUnit> {
    let Some(owner_node) = scala_enclosing_definition_node(node) else {
        return Vec::new();
    };
    let mut ancestor_types = Vec::new();
    scala_collect_extends_type_text(owner_node, ctx.source, &mut ancestor_types);
    for ancestor_type in ancestor_types {
        let Some(owner_fqn) = resolver.resolve(&ancestor_type) else {
            continue;
        };
        let candidates = scala_member_candidate_units(ctx, &owner_fqn, member);
        if !candidates.is_empty() {
            return candidates;
        }
    }
    Vec::new()
}

fn scala_enclosing_definition_node(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "class_definition" | "object_definition" | "trait_definition" | "enum_definition"
        ) {
            return Some(parent);
        }
        node = parent;
    }
    None
}

fn scala_collect_extends_type_text(node: Node<'_>, source: &str, out: &mut Vec<String>) {
    let in_extends = node.kind() == "extends_clause";
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if in_extends
            && matches!(
                child.kind(),
                "type_identifier" | "stable_type_identifier" | "generic_type"
            )
        {
            let text = scala_node_text(child, source).trim();
            if !text.is_empty() {
                out.push(text.to_string());
            }
            continue;
        }
        scala_collect_extends_type_text(child, source, out);
    }
}

fn scala_member_not_found(
    _ctx: ScalaLookupCtx<'_>,
    owner_fqn: &str,
    member: &str,
) -> DefinitionLookupOutcome {
    no_definition(
        "unsupported_scala_receiver",
        format!(
            "receiver for Scala member `{member}` resolved to `{owner_fqn}`, but `{owner_fqn}.{member}` was not indexed"
        ),
    )
}

fn scala_receiver_type_fqn(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    receiver: Node<'_>,
    cutoff_start: usize,
) -> Option<String> {
    match receiver.kind() {
        "identifier" | "type_identifier" => {
            let name = scala_node_text(receiver, ctx.source).trim();
            if name == "this" {
                return ClassRangeIndex::build(ctx.analyzer, ctx.file)
                    .enclosing(receiver.start_byte())
                    .map(str::to_string);
            }
            let bindings = scala_bindings_before(resolver, ctx.source, root, cutoff_start);
            first_precise(&bindings, name).or_else(|| {
                scala_enclosing_class_parameter_type(
                    ctx.scala,
                    ctx.analyzer,
                    ctx.file,
                    receiver,
                    name,
                    resolver,
                    ctx.source,
                )
                .or_else(|| {
                    (!bindings.is_shadowed(name))
                        .then(|| resolver.resolve(name))
                        .flatten()
                })
            })
        }
        _ => None,
    }
}

fn scala_enclosing_class_parameter_type(
    scala: &ScalaAnalyzer,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    node: Node<'_>,
    name: &str,
    resolver: &ScalaNameResolver,
    source: &str,
) -> Option<String> {
    let current_class = ClassRangeIndex::build(analyzer, file)
        .enclosing(node.start_byte())
        .map(str::to_string);
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "class_definition" {
            let parameters = parent.child_by_field_name("class_parameters")?;
            let mut cursor = parameters.walk();
            for parameter in parameters.named_children(&mut cursor) {
                if !matches!(parameter.kind(), "parameter" | "class_parameter") {
                    continue;
                }
                let Some(param_name) = parameter.child_by_field_name("name") else {
                    continue;
                };
                if scala_node_text(param_name, source).trim() != name {
                    continue;
                }
                if scala_active_path_declares_name_after(
                    parent,
                    source,
                    name,
                    parameter.end_byte(),
                    node.start_byte(),
                ) {
                    return None;
                }
                return parameter.child_by_field_name("type").and_then(|type_node| {
                    let type_text = scala_node_text(type_node, source);
                    scala_resolve_type_annotation(resolver, type_text).or_else(|| {
                        current_class
                            .as_deref()
                            .and_then(|class_fqn| scala_same_package_type_fqn(class_fqn, type_text))
                            .or_else(|| {
                                scala_package_name_of(scala, file)
                                    .and_then(|package| scala_package_type_fqn(&package, type_text))
                            })
                    })
                });
            }
            return None;
        }
        current = parent.parent();
    }
    None
}

fn scala_active_path_declares_name_after(
    node: Node<'_>,
    source: &str,
    name: &str,
    lower_bound: usize,
    target_byte: usize,
) -> bool {
    if target_byte < node.start_byte() || node.end_byte() <= target_byte {
        return false;
    }

    let mut containing_child = None;
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.start_byte() <= target_byte && target_byte < child.end_byte() {
            containing_child = Some(child);
        }
        if child.start_byte() >= target_byte || child.end_byte() <= lower_bound {
            continue;
        }
        if scala_node_declares_name_before(child, source, name, lower_bound, target_byte) {
            return true;
        }
    }

    containing_child.is_some_and(|child| {
        scala_active_path_declares_name_after(child, source, name, lower_bound, target_byte)
    })
}

fn scala_node_declares_name_before(
    node: Node<'_>,
    source: &str,
    name: &str,
    lower_bound: usize,
    target_byte: usize,
) -> bool {
    match node.kind() {
        "parameter" | "class_parameter" => {
            node.child_by_field_name("name").is_some_and(|name_node| {
                lower_bound <= name_node.start_byte()
                    && name_node.start_byte() < target_byte
                    && scala_node_text(name_node, source).trim() == name
            })
        }
        "parameters" | "class_parameters" => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor).any(|child| {
                scala_node_declares_name_before(child, source, name, lower_bound, target_byte)
            })
        }
        "val_definition" | "var_definition" => {
            if node.start_byte() >= target_byte {
                return false;
            }
            node.child_by_field_name("pattern").is_some_and(|pattern| {
                lower_bound <= pattern.start_byte()
                    && scala_pattern_names(pattern, source).contains(&name)
            })
        }
        "function_definition" => node.child_by_field_name("name").is_some_and(|name_node| {
            lower_bound <= name_node.start_byte()
                && name_node.start_byte() < target_byte
                && scala_node_text(name_node, source).trim() == name
        }),
        _ => false,
    }
}

fn scala_same_package_type_fqn(current_class_fqn: &str, type_text: &str) -> Option<String> {
    let package = current_class_fqn
        .rsplit_once('.')
        .map(|(package, _)| package)?;
    scala_package_type_fqn(package, type_text)
}

fn scala_package_type_fqn(package: &str, type_text: &str) -> Option<String> {
    let simple = scala_simple_name(type_text);
    if simple.is_empty() || simple.contains('.') {
        return None;
    }
    if package.is_empty() {
        Some(simple.to_string())
    } else {
        Some(format!("{package}.{simple}"))
    }
}

fn scala_resolve_type_annotation(resolver: &ScalaNameResolver, type_text: &str) -> Option<String> {
    let trimmed = type_text.trim();
    if let Some(base_type) = trimmed.strip_suffix(".type") {
        return resolver.resolve(base_type).map(|fqn| {
            if fqn.ends_with('$') {
                fqn
            } else {
                format!("{fqn}$")
            }
        });
    }
    let fqn = resolver
        .resolve(type_text)
        .or_else(|| scala_type_base_text(trimmed).and_then(|base| resolver.resolve(base)))?;
    Some(fqn.trim_end_matches('$').to_string())
}

fn scala_type_base_text(type_text: &str) -> Option<&str> {
    let base = type_text
        .split(['[', '<'])
        .next()
        .unwrap_or(type_text)
        .trim();
    (!base.is_empty() && base != type_text.trim()).then_some(base)
}

fn scala_fqn_outcome(
    support: &DefinitionLookupIndex,
    fqn: &str,
    reference: &str,
) -> DefinitionLookupOutcome {
    let candidates = support.fqn(fqn);
    if candidates.is_empty() {
        no_definition(
            "no_indexed_definition",
            format!("`{reference}` resolved to `{fqn}`, but no indexed definition was found"),
        )
    } else {
        candidates_outcome(candidates)
    }
}

fn scala_enclosing_class(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    byte: usize,
) -> Option<CodeUnit> {
    let fqn = ClassRangeIndex::build(analyzer, file)
        .enclosing(byte)?
        .to_string();
    analyzer.definitions(&fqn).next().cloned()
}

const SCALA_SCOPE_NODES: &[&str] = &[
    "class_definition",
    "object_definition",
    "trait_definition",
    "enum_definition",
    "function_definition",
    "block",
    "indented_block",
    "case_clause",
    "lambda_expression",
];

fn scala_bindings_before(
    resolver: &ScalaNameResolver,
    source: &str,
    root: Node<'_>,
    cutoff_start: usize,
) -> LocalInferenceEngine<String> {
    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    scala_seed_active_path(resolver, source, root, cutoff_start, &mut bindings);
    bindings
}

fn scala_seed_active_path(
    resolver: &ScalaNameResolver,
    source: &str,
    node: Node<'_>,
    cutoff_start: usize,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.start_byte() >= cutoff_start {
            continue;
        }
        let enters_scope = SCALA_SCOPE_NODES.contains(&node.kind());
        if enters_scope && !(node.start_byte() <= cutoff_start && cutoff_start < node.end_byte()) {
            continue;
        }
        if enters_scope {
            bindings.enter_scope();
        }
        match node.kind() {
            "class_definition" | "function_definition" => {
                scala_seed_parameters(resolver, source, node, cutoff_start, bindings)
            }
            "val_definition" | "var_definition" if node.start_byte() < cutoff_start => {
                scala_seed_value_definition(resolver, source, node, cutoff_start, bindings)
            }
            _ => {}
        }

        let mut cursor = node.walk();
        let mut children: Vec<_> = node
            .named_children(&mut cursor)
            .take_while(|child| child.start_byte() < cutoff_start)
            .collect();
        children.reverse();
        stack.extend(children);
    }
}

fn scala_seed_parameters(
    resolver: &ScalaNameResolver,
    source: &str,
    node: Node<'_>,
    cutoff_start: usize,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if !matches!(child.kind(), "parameters" | "class_parameters")
            || child.start_byte() >= cutoff_start
        {
            continue;
        }
        let mut inner = child.walk();
        for parameter in child.named_children(&mut inner) {
            if matches!(parameter.kind(), "parameter" | "class_parameter")
                && parameter.start_byte() < cutoff_start
            {
                scala_seed_parameter(resolver, source, parameter, cutoff_start, bindings);
            }
        }
    }
}

fn scala_seed_parameter(
    resolver: &ScalaNameResolver,
    source: &str,
    parameter: Node<'_>,
    cutoff_start: usize,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let Some(name) = parameter.child_by_field_name("name") else {
        return;
    };
    if name.start_byte() >= cutoff_start {
        return;
    }
    let binding_name = scala_node_text(name, source).trim();
    if binding_name.is_empty() {
        return;
    }
    let resolved = parameter
        .child_by_field_name("type")
        .filter(|type_node| type_node.end_byte() <= cutoff_start)
        .and_then(|type_node| {
            let type_text = scala_node_text(type_node, source);
            scala_resolve_type_annotation(resolver, type_text)
        });
    scala_seed_typed(binding_name, resolved, bindings);
}

fn scala_seed_value_definition(
    resolver: &ScalaNameResolver,
    source: &str,
    node: Node<'_>,
    cutoff_start: usize,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let resolved = node
        .child_by_field_name("type")
        .filter(|type_node| type_node.end_byte() <= cutoff_start)
        .and_then(|type_node| {
            scala_resolve_type_annotation(resolver, scala_node_text(type_node, source))
        })
        .or_else(|| {
            node.child_by_field_name("value")
                .filter(|value| value.end_byte() <= cutoff_start)
                .and_then(|value| scala_constructed_type(value, resolver, source))
                .or_else(|| {
                    scala_constructor_type_text(scala_node_text(node, source))
                        .and_then(|type_text| scala_resolve_type_annotation(resolver, type_text))
                })
        });
    let Some(pattern) = node.child_by_field_name("pattern") else {
        return;
    };
    if pattern.start_byte() >= cutoff_start {
        return;
    }
    for name in scala_pattern_names(pattern, source) {
        scala_seed_typed(name, resolved.clone(), bindings);
    }
}

fn scala_constructed_type(
    node: Node<'_>,
    resolver: &ScalaNameResolver,
    source: &str,
) -> Option<String> {
    if node.kind() == "call_expression"
        && let Some(function) = node
            .child_by_field_name("function")
            .or_else(|| node.named_child(0))
    {
        return scala_constructed_type(function, resolver, source);
    }
    if !matches!(
        node.kind(),
        "instance_expression" | "generic_type" | "type_identifier" | "identifier"
    ) {
        return None;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == "type_identifier" || child.kind() == "generic_type")
        .or_else(|| {
            matches!(
                node.kind(),
                "type_identifier" | "generic_type" | "identifier"
            )
            .then_some(node)
        })
        .and_then(|type_node| {
            scala_resolve_type_annotation(resolver, scala_node_text(type_node, source))
        })
}

fn scala_constructor_type_text(value_text: &str) -> Option<&str> {
    let trimmed = value_text.trim_start();
    let value = if let Some(after_keyword) = trimmed
        .strip_prefix("val ")
        .or_else(|| trimmed.strip_prefix("var "))
    {
        after_keyword.split_once('=')?.1.trim_start()
    } else {
        trimmed
    };
    let value = value.strip_prefix("new ").unwrap_or(value).trim_start();
    let end = value
        .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '.'))
        .unwrap_or(value.len());
    if end == 0 {
        return None;
    }
    let type_text = &value[..end];
    let simple_name = type_text.rsplit('.').next().unwrap_or(type_text);
    simple_name
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_uppercase())
        .then_some(type_text)
}

fn scala_pattern_names<'a>(node: Node<'_>, source: &'a str) -> Vec<&'a str> {
    match node.kind() {
        "identifier" | "operator_identifier" => {
            let name = scala_node_text(node, source).trim();
            if name.is_empty() {
                Vec::new()
            } else {
                vec![name]
            }
        }
        _ => {
            let mut names = Vec::new();
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                names.extend(scala_pattern_names(child, source));
            }
            names
        }
    }
}

fn scala_seed_typed(
    name: &str,
    resolved: Option<String>,
    bindings: &mut LocalInferenceEngine<String>,
) {
    match resolved {
        Some(fqn) => bindings.seed_symbol(name.to_string(), fqn),
        None => bindings.declare_shadow(name.to_string()),
    }
}

fn scala_import_boundary_for_name(
    scala: &ScalaAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    name: &str,
) -> bool {
    let simple = scala_simple_name(name);
    for import in scala.import_info_of(file) {
        let Some(path) = scala_import_path(import) else {
            continue;
        };
        if import.is_wildcard {
            if simple.chars().next().is_some_and(char::is_uppercase)
                && !scala_workspace_package_exists(support, &path)
            {
                return true;
            }
            continue;
        }
        let local_name = import
            .identifier
            .as_deref()
            .unwrap_or_else(|| path.rsplit('.').next().unwrap_or(path.as_str()));
        if local_name == simple && supportless_scala_import_target_missing(support, &path) {
            return true;
        }
    }
    false
}

fn supportless_scala_import_target_missing(support: &DefinitionLookupIndex, path: &str) -> bool {
    let normalized = path.replace("$.", ".").trim_end_matches('$').to_string();
    !support.fqn_exists(&normalized) && !support.normalized_fqn_exists(&normalized)
}

fn scala_workspace_package_exists(support: &DefinitionLookupIndex, package: &str) -> bool {
    support.package_exists(package)
}

fn scala_simple_name(name: &str) -> &str {
    name.split(['[', '(', '{', '.', ' ', '<'])
        .next()
        .unwrap_or(name)
        .trim()
}

fn resolve_java(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    let Some(java) = resolve_analyzer::<JavaAnalyzer>(analyzer) else {
        return no_definition("java_analyzer_unavailable", "Java analyzer is unavailable");
    };
    let Some(tree) = tree else {
        return no_definition("java_parse_failed", "Java source could not be parsed");
    };

    let root = tree.root_node();
    let Some(node) = smallest_named_node_covering(root, site.focus_start_byte, site.focus_end_byte)
    else {
        return no_definition(
            "no_indexed_definition",
            format!(
                "`{}` did not resolve to an indexed Java definition",
                site.text
            ),
        );
    };

    if is_java_declaration_or_import_name(node) {
        return no_definition(
            "declaration_or_import_site",
            format!("`{}` is not a Java reference site", site.text),
        );
    }

    match node.kind() {
        "type_identifier" | "scoped_type_identifier" | "generic_type" => {
            resolve_java_type_reference(analyzer, java, support, file, source, node)
        }
        "object_creation_expression" => node
            .child_by_field_name("type")
            .map(|type_node| {
                resolve_java_type_reference(analyzer, java, support, file, source, type_node)
            })
            .unwrap_or_else(|| {
                no_definition(
                    "no_indexed_definition",
                    format!("`{}` did not resolve to an indexed Java type", site.text),
                )
            }),
        "method_invocation" => {
            resolve_java_method_invocation(analyzer, support, file, source, root, node)
        }
        "method_reference" => {
            resolve_java_method_reference(analyzer, java, support, file, source, root, node)
        }
        "field_access" => resolve_java_field_access(analyzer, support, file, source, root, node),
        "identifier" => {
            if let Some(parent) = node.parent() {
                match parent.kind() {
                    "method_invocation" => {
                        return resolve_java_method_invocation(
                            analyzer, support, file, source, root, parent,
                        );
                    }
                    "field_access" => {
                        return resolve_java_field_access(
                            analyzer, support, file, source, root, parent,
                        );
                    }
                    "method_reference" => {
                        return resolve_java_method_reference(
                            analyzer, java, support, file, source, root, parent,
                        );
                    }
                    _ => {}
                }
            }
            resolve_java_bare_identifier(analyzer, java, support, file, source, node)
        }
        _ => no_definition(
            "unsupported_java_reference_shape",
            format!(
                "`{}` is a Java `{}` reference shape that get_definition does not resolve yet",
                site.text,
                node.kind()
            ),
        ),
    }
}

fn parse_java_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .ok()?;
    parser.parse(source, None)
}

fn smallest_named_node_covering<'tree>(
    mut node: Node<'tree>,
    start: usize,
    end: usize,
) -> Option<Node<'tree>> {
    if node.end_byte() < end || node.start_byte() > start {
        return None;
    }
    loop {
        let mut cursor = node.walk();
        let mut containing_child = None;
        for child in node.named_children(&mut cursor) {
            if child.start_byte() <= start && child.end_byte() >= end {
                containing_child = Some(child);
                break;
            }
        }
        match containing_child {
            Some(child) => node = child,
            None => return Some(node),
        }
    }
}

fn is_java_declaration_or_import_name(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if parent.kind() == "import_declaration" || parent.kind() == "package_declaration" {
        return true;
    }
    parent.child_by_field_name("name") == Some(node)
        && matches!(
            parent.kind(),
            "class_declaration"
                | "interface_declaration"
                | "enum_declaration"
                | "record_declaration"
                | "method_declaration"
                | "constructor_declaration"
                | "field_declaration"
                | "variable_declarator"
                | "formal_parameter"
        )
}

fn resolve_java_type_reference(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
) -> DefinitionLookupOutcome {
    let raw = java_node_text(node, source);
    let normalized = normalize_java_type_text(raw);
    if normalized.is_empty() {
        return no_definition("no_reference_text", "Java type reference is blank");
    }
    if let Some(unit) = java.resolve_type_name_in_file(file, normalized) {
        return candidates_outcome(vec![unit]);
    }
    if let Some(unit) = java_nested_type_from_context(analyzer, file, normalized, node.start_byte())
    {
        return candidates_outcome(vec![unit]);
    }
    if java_import_boundary_for_type(java, support, file, normalized) {
        return boundary(format!(
            "`{normalized}` appears to cross a Java import boundary not indexed in this workspace"
        ));
    }
    no_definition(
        "no_indexed_definition",
        format!("`{normalized}` did not resolve to an indexed Java type"),
    )
}

fn resolve_java_method_invocation(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    node: Node<'_>,
) -> DefinitionLookupOutcome {
    let Some(name_node) = node.child_by_field_name("name") else {
        return no_definition("no_method_name", "Java method invocation has no name");
    };
    let name = java_node_text(name_node, source);
    if name.is_empty() {
        return no_definition("no_method_name", "Java method invocation has a blank name");
    }

    if let Some(object) = node.child_by_field_name("object") {
        if let Some(owner) = java_receiver_type(analyzer, file, source, root, object) {
            return java_member_candidates(analyzer, support, &owner.fq_name(), name);
        }
        return no_definition(
            "unsupported_java_receiver",
            format!("receiver for Java method `{name}` is not resolved"),
        );
    }

    let static_import = java_static_import_candidates(analyzer, support, file, name);
    if static_import.status != DefinitionLookupStatus::NoDefinition {
        return static_import;
    }

    let class_ranges = ClassRangeIndex::build(analyzer, file);
    if let Some(owner_fqn) = class_ranges.enclosing(name_node.start_byte()) {
        return java_member_candidates(analyzer, support, owner_fqn, name);
    }

    no_definition(
        "no_indexed_definition",
        format!("`{name}` did not resolve to an indexed Java method"),
    )
}

fn resolve_java_method_reference(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    node: Node<'_>,
) -> DefinitionLookupOutcome {
    let text = java_node_text(node, source);
    let Some(separator) = text.find("::") else {
        return no_definition(
            "malformed_java_method_reference",
            "Java method reference has no `::` separator",
        );
    };
    let receiver_text = text[..separator].trim();
    let member = java_method_reference_member_name(text[separator + 2..].trim());
    if receiver_text.is_empty() || member.is_empty() {
        return no_definition(
            "malformed_java_method_reference",
            "Java method reference has a blank receiver or member",
        );
    }
    if member == "new" {
        return resolve_java_type_reference(analyzer, java, support, file, source, node);
    }

    let separator_byte = node.start_byte() + separator;
    let receiver_node = java_method_reference_receiver_node(node, separator_byte);
    let owner = receiver_node
        .and_then(|receiver| java_receiver_type(analyzer, file, source, root, receiver))
        .or_else(|| {
            java_type_text_with_context(
                analyzer,
                java,
                file,
                normalize_java_type_text(receiver_text),
                node.start_byte(),
            )
        });
    if let Some(owner) = owner {
        return java_member_candidates(analyzer, support, &owner.fq_name(), member);
    }

    no_definition(
        "unsupported_java_receiver",
        format!("receiver for Java method reference `{member}` is not resolved"),
    )
}

fn java_method_reference_receiver_node(node: Node<'_>, separator_byte: usize) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| child.end_byte() <= separator_byte)
        .last()
}

fn java_method_reference_member_name(mut text: &str) -> &str {
    if let Some(rest) = text.strip_prefix('<')
        && let Some((_, after_type_args)) = rest.split_once('>')
    {
        text = after_type_args.trim_start();
    }
    let end = text
        .char_indices()
        .find(|(_, ch)| *ch != '_' && !ch.is_ascii_alphanumeric())
        .map(|(idx, _)| idx)
        .unwrap_or(text.len());
    &text[..end]
}

fn resolve_java_field_access(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    node: Node<'_>,
) -> DefinitionLookupOutcome {
    let Some(field_node) = node.child_by_field_name("field") else {
        return no_definition("no_field_name", "Java field access has no field name");
    };
    let field = java_node_text(field_node, source);
    let Some(object) = node.child_by_field_name("object") else {
        return no_definition("no_field_receiver", "Java field access has no receiver");
    };
    if let Some(owner) = java_receiver_type(analyzer, file, source, root, object) {
        return java_member_candidates(analyzer, support, &owner.fq_name(), field);
    }
    no_definition(
        "unsupported_java_receiver",
        format!("receiver for Java field `{field}` is not resolved"),
    )
}

fn resolve_java_bare_identifier(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
) -> DefinitionLookupOutcome {
    let name = java_node_text(node, source);
    if let Some(unit) = java.resolve_type_name_in_file(file, name) {
        return candidates_outcome(vec![unit]);
    }
    let static_import = java_static_import_candidates(analyzer, support, file, name);
    if static_import.status != DefinitionLookupStatus::NoDefinition {
        return static_import;
    }
    if java_import_boundary_for_type(java, support, file, name) {
        return boundary(format!(
            "`{name}` appears to cross a Java import boundary not indexed in this workspace"
        ));
    }
    no_definition(
        "no_indexed_definition",
        format!("`{name}` did not resolve to an indexed Java definition"),
    )
}

fn java_receiver_type(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    object: Node<'_>,
) -> Option<CodeUnit> {
    let java = resolve_analyzer::<JavaAnalyzer>(analyzer)?;
    java_receiver_type_for_java(analyzer, java, file, source, root, object).or_else(|| {
        matches!(object.kind(), "this" | "super")
            .then(|| {
                ClassRangeIndex::build(analyzer, file)
                    .enclosing(object.start_byte())
                    .and_then(|fqn| analyzer.definitions(fqn).next().cloned())
            })
            .flatten()
    })
}

fn java_receiver_type_for_java(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    object: Node<'_>,
) -> Option<CodeUnit> {
    match object.kind() {
        "object_creation_expression" => object.child_by_field_name("type").and_then(|type_node| {
            java_type_from_node_with_context(analyzer, java, file, source, type_node)
        }),
        "type_identifier" | "scoped_type_identifier" | "generic_type" => {
            let raw = java_node_text(object, source);
            java_type_text_with_context(
                analyzer,
                java,
                file,
                normalize_java_type_text(raw),
                object.start_byte(),
            )
        }
        "identifier" => {
            let name = java_node_text(object, source);
            java_type_of_identifier_before(java, file, source, root, name, object.start_byte())
                .or_else(|| {
                    java_lambda_parameter_type_before(
                        analyzer,
                        java,
                        analyzer.definition_lookup_index(),
                        file,
                        source,
                        root,
                        name,
                        object.start_byte(),
                    )
                })
                .or_else(|| {
                    (!java_identifier_binding_before(source, root, name, object.start_byte()))
                        .then(|| java.resolve_type_name_in_file(file, name))
                        .flatten()
                })
        }
        _ => None,
    }
}

fn java_type_from_node_with_context(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    file: &ProjectFile,
    source: &str,
    type_node: Node<'_>,
) -> Option<CodeUnit> {
    java_type_text_with_context(
        analyzer,
        java,
        file,
        normalize_java_type_text(java_node_text(type_node, source)),
        type_node.start_byte(),
    )
}

fn java_type_text_with_context(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    file: &ProjectFile,
    normalized: &str,
    byte: usize,
) -> Option<CodeUnit> {
    java.resolve_type_name_in_file(file, normalized)
        .or_else(|| java_nested_type_from_context(analyzer, file, normalized, byte))
}

fn java_nested_type_from_context(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    normalized: &str,
    byte: usize,
) -> Option<CodeUnit> {
    if normalized.contains('.') || normalized.is_empty() {
        return None;
    }
    let class_ranges = ClassRangeIndex::build(analyzer, file);
    let mut owner = class_ranges
        .enclosing(byte)
        .and_then(|fqn| analyzer.definitions(fqn).next().cloned());
    while let Some(current) = owner {
        let child_fqn = format!("{}.{}", current.fq_name(), normalized);
        if let Some(child) = analyzer
            .definitions(&child_fqn)
            .find(|code_unit| code_unit.is_class())
            .cloned()
        {
            return Some(child);
        }
        owner = analyzer.parent_of(&current);
    }
    None
}

fn java_type_of_identifier_before(
    java: &JavaAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    name: &str,
    before_byte: usize,
) -> Option<CodeUnit> {
    let mut found = None;
    collect_java_typed_binding_before(java, file, source, root, name, before_byte, &mut found);
    found
}

#[allow(clippy::too_many_arguments)]
fn java_lambda_parameter_type_before(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    name: &str,
    before_byte: usize,
) -> Option<CodeUnit> {
    let type_text = java_lambda_parameter_type_text_before(
        analyzer,
        java,
        support,
        file,
        source,
        root,
        name,
        before_byte,
    )?;
    java_type_text_with_context(
        analyzer,
        java,
        file,
        normalize_java_type_text(&type_text),
        before_byte,
    )
}

#[allow(clippy::too_many_arguments)]
fn java_lambda_parameter_type_text_before(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    name: &str,
    before_byte: usize,
) -> Option<String> {
    let lambda = java_matching_lambda_parameter(root, source, name, before_byte)?;
    let invocation = java_ancestor_method_invocation(lambda)?;
    let method = invocation
        .child_by_field_name("name")
        .map(|node| java_node_text(node, source))?;
    let object = invocation.child_by_field_name("object")?;
    match method {
        "filter" => {
            if object.kind() == "method_invocation"
                && object
                    .child_by_field_name("name")
                    .is_some_and(|node| java_node_text(node, source) == "stream")
                && let Some(collection) = object.child_by_field_name("object")
            {
                return java_collection_element_type_text(
                    analyzer,
                    java,
                    support,
                    file,
                    source,
                    root,
                    collection,
                    lambda.start_byte(),
                );
            }
            java_collection_element_type_text(
                analyzer,
                java,
                support,
                file,
                source,
                root,
                object,
                lambda.start_byte(),
            )
        }
        "forEach" => java_collection_element_type_text(
            analyzer,
            java,
            support,
            file,
            source,
            root,
            object,
            lambda.start_byte(),
        ),
        _ => None,
    }
}

fn java_matching_lambda_parameter<'tree>(
    root: Node<'tree>,
    source: &str,
    name: &str,
    before_byte: usize,
) -> Option<Node<'tree>> {
    let mut best = None;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.start_byte() > before_byte || node.end_byte() < before_byte {
            continue;
        }
        if node.kind() == "lambda_expression"
            && java_lambda_has_parameter(node, source, name, before_byte)
        {
            let span = node.end_byte() - node.start_byte();
            if best
                .map(|current: Node<'_>| span < current.end_byte() - current.start_byte())
                .unwrap_or(true)
            {
                best = Some(node);
            }
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.start_byte() <= before_byte && child.end_byte() >= before_byte {
                stack.push(child);
            }
        }
    }
    best
}

fn java_lambda_has_parameter(
    lambda: Node<'_>,
    source: &str,
    name: &str,
    before_byte: usize,
) -> bool {
    let mut cursor = lambda.walk();
    for child in lambda.named_children(&mut cursor) {
        if child.start_byte() >= before_byte {
            continue;
        }
        if child.kind() == "identifier" && java_node_text(child, source) == name {
            return true;
        }
        if matches!(child.kind(), "formal_parameters" | "inferred_parameters") {
            let mut inner = child.walk();
            if child
                .named_children(&mut inner)
                .any(|param| param.kind() == "identifier" && java_node_text(param, source) == name)
            {
                return true;
            }
        }
    }
    false
}

fn java_ancestor_method_invocation(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        if parent.kind() == "method_invocation" {
            return Some(parent);
        }
        node = parent;
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn java_collection_element_type_text(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
    before_byte: usize,
) -> Option<String> {
    if expression.kind() == "method_invocation"
        && expression
            .child_by_field_name("name")
            .is_some_and(|node| java_node_text(node, source) == "values")
        && let Some(object) = expression.child_by_field_name("object")
    {
        let type_text = java_expression_type_text(
            analyzer,
            java,
            support,
            file,
            source,
            root,
            object,
            before_byte,
        )?;
        if !java_is_map_type(&type_text) {
            return None;
        }
        return java_generic_arg(&type_text, 1);
    }
    let type_text = java_expression_type_text(
        analyzer,
        java,
        support,
        file,
        source,
        root,
        expression,
        before_byte,
    )?;
    if !java_is_collection_type(&type_text) {
        return None;
    }
    java_generic_arg(&type_text, 0)
}

#[allow(clippy::too_many_arguments)]
fn java_expression_type_text(
    analyzer: &dyn IAnalyzer,
    java: &JavaAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    expression: Node<'_>,
    before_byte: usize,
) -> Option<String> {
    match expression.kind() {
        "identifier" => {
            let name = java_node_text(expression, source);
            java_identifier_type_text_before(java, file, source, root, name, before_byte).or_else(
                || {
                    java_lambda_parameter_type_text_before(
                        analyzer,
                        java,
                        support,
                        file,
                        source,
                        root,
                        name,
                        before_byte,
                    )
                },
            )
        }
        "field_access" => {
            let field_node = expression.child_by_field_name("field")?;
            let field = java_node_text(field_node, source);
            let object = expression.child_by_field_name("object")?;
            let owner = java_receiver_type(analyzer, file, source, root, object)?;
            let unit = support
                .fqn(&format!("{}.{}", owner.fq_name(), field))
                .into_iter()
                .next()?;
            let signature = unit
                .signature()
                .map(str::to_string)
                .or_else(|| analyzer.signatures(&unit).iter().next().cloned())?;
            java_field_type_text_from_signature(&signature, field)
        }
        "method_invocation" => {
            if expression
                .child_by_field_name("name")
                .is_some_and(|node| java_node_text(node, source) == "values")
                && let Some(object) = expression.child_by_field_name("object")
            {
                let type_text = java_expression_type_text(
                    analyzer,
                    java,
                    support,
                    file,
                    source,
                    root,
                    object,
                    before_byte,
                )?;
                if !java_is_map_type(&type_text) {
                    return None;
                }
                return java_generic_arg(&type_text, 1);
            }
            None
        }
        _ => None,
    }
}

fn java_identifier_type_text_before(
    java: &JavaAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    name: &str,
    before_byte: usize,
) -> Option<String> {
    let mut found = None;
    collect_java_type_text_binding_before(java, file, source, root, name, before_byte, &mut found);
    found
}

fn collect_java_type_text_binding_before(
    java: &JavaAnalyzer,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    name: &str,
    before_byte: usize,
    found: &mut Option<String>,
) {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.start_byte() >= before_byte {
            continue;
        }
        match node.kind() {
            "local_variable_declaration" | "field_declaration" => {
                if let Some(type_node) = node.child_by_field_name("type") {
                    let type_text = normalize_java_type_text(java_node_text(type_node, source));
                    let mut cursor = node.walk();
                    for child in node.named_children(&mut cursor) {
                        if child.kind() == "variable_declarator"
                            && let Some(name_node) = child.child_by_field_name("name")
                            && name_node.start_byte() < before_byte
                            && java_node_text(name_node, source) == name
                        {
                            *found = Some(type_text.to_string());
                        }
                    }
                }
            }
            "formal_parameter" => {
                if let Some(name_node) = node.child_by_field_name("name")
                    && name_node.start_byte() < before_byte
                    && java_node_text(name_node, source) == name
                    && let Some(type_node) = node.child_by_field_name("type")
                {
                    *found = Some(
                        normalize_java_type_text(java_node_text(type_node, source)).to_string(),
                    );
                }
            }
            _ => {}
        }
        let mut cursor = node.walk();
        let mut children: Vec<_> = node.named_children(&mut cursor).collect();
        children.reverse();
        for child in children {
            if child.start_byte() < before_byte {
                stack.push(child);
            }
        }
    }
    if found.is_none() && java.resolve_type_name_in_file(file, name).is_some() {
        *found = Some(name.to_string());
    }
}

fn java_field_type_text_from_signature(signature: &str, field: &str) -> Option<String> {
    let before_initializer = signature.split('=').next().unwrap_or(signature);
    let field_start = before_initializer.rfind(field)?;
    let mut type_text = before_initializer[..field_start].trim();
    for modifier in [
        "public",
        "protected",
        "private",
        "static",
        "final",
        "transient",
        "volatile",
    ] {
        type_text = type_text
            .strip_prefix(modifier)
            .unwrap_or(type_text)
            .trim_start();
    }
    (!type_text.is_empty()).then(|| type_text.to_string())
}

fn java_generic_arg(type_text: &str, index: usize) -> Option<String> {
    let start = type_text.find('<')?;
    let end = type_text.rfind('>')?;
    if end <= start {
        return None;
    }
    let mut args = Vec::new();
    let mut depth = 0usize;
    let mut arg_start = start + 1;
    let inner = &type_text[start + 1..end];
    for (offset, ch) in inner.char_indices() {
        match ch {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                args.push(inner[arg_start - start - 1..offset].trim().to_string());
                arg_start = start + 1 + offset + ch.len_utf8();
            }
            _ => {}
        }
    }
    args.push(type_text[arg_start..end].trim().to_string());
    args.get(index).filter(|arg| !arg.is_empty()).cloned()
}

fn java_is_map_type(type_text: &str) -> bool {
    matches!(
        java_raw_type_name(type_text).as_deref(),
        Some("Map")
            | Some("HashMap")
            | Some("LinkedHashMap")
            | Some("NavigableMap")
            | Some("SortedMap")
            | Some("TreeMap")
            | Some("ConcurrentMap")
            | Some("ConcurrentHashMap")
    )
}

fn java_is_collection_type(type_text: &str) -> bool {
    matches!(
        java_raw_type_name(type_text).as_deref(),
        Some("Iterable")
            | Some("Collection")
            | Some("List")
            | Some("ArrayList")
            | Some("LinkedList")
            | Some("Set")
            | Some("HashSet")
            | Some("LinkedHashSet")
            | Some("SortedSet")
            | Some("NavigableSet")
            | Some("Stream")
    )
}

fn java_raw_type_name(type_text: &str) -> Option<String> {
    let raw = type_text
        .trim()
        .split('<')
        .next()
        .unwrap_or(type_text)
        .trim();
    let name = raw.rsplit('.').next().unwrap_or(raw).trim();
    (!name.is_empty()).then(|| name.to_string())
}

fn java_identifier_binding_before(
    source: &str,
    root: Node<'_>,
    name: &str,
    before_byte: usize,
) -> bool {
    let mut found = false;
    collect_java_identifier_binding_before(source, root, name, before_byte, &mut found);
    found
}

fn collect_java_identifier_binding_before(
    source: &str,
    node: Node<'_>,
    name: &str,
    before_byte: usize,
    found: &mut bool,
) {
    if *found {
        return;
    }
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.start_byte() >= before_byte {
            continue;
        }
        match node.kind() {
            "local_variable_declaration" | "field_declaration" => {
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    if child.kind() == "variable_declarator"
                        && let Some(name_node) = child.child_by_field_name("name")
                        && name_node.start_byte() < before_byte
                        && java_node_text(name_node, source) == name
                    {
                        *found = true;
                        return;
                    }
                }
            }
            "formal_parameter" => {
                if let Some(name_node) = node.child_by_field_name("name")
                    && name_node.start_byte() < before_byte
                    && java_node_text(name_node, source) == name
                {
                    *found = true;
                    return;
                }
            }
            _ => {}
        }
        let mut cursor = node.walk();
        let mut children: Vec<_> = node.named_children(&mut cursor).collect();
        children.reverse();
        for child in children {
            if child.start_byte() < before_byte {
                stack.push(child);
            }
        }
    }
}

fn collect_java_typed_binding_before(
    java: &JavaAnalyzer,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    name: &str,
    before_byte: usize,
    found: &mut Option<CodeUnit>,
) {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.start_byte() >= before_byte {
            continue;
        }
        match node.kind() {
            "local_variable_declaration" | "field_declaration" => {
                if let Some(resolved) = node
                    .child_by_field_name("type")
                    .and_then(|type_node| java_type_from_node(java, file, source, type_node))
                {
                    let mut cursor = node.walk();
                    for child in node.named_children(&mut cursor) {
                        if child.kind() == "variable_declarator"
                            && let Some(name_node) = child.child_by_field_name("name")
                            && name_node.start_byte() < before_byte
                            && java_node_text(name_node, source) == name
                        {
                            *found = Some(resolved.clone());
                        }
                    }
                }
            }
            "formal_parameter" => {
                if let Some(name_node) = node.child_by_field_name("name")
                    && name_node.start_byte() < before_byte
                    && java_node_text(name_node, source) == name
                    && let Some(resolved) = node
                        .child_by_field_name("type")
                        .and_then(|type_node| java_type_from_node(java, file, source, type_node))
                {
                    *found = Some(resolved);
                }
            }
            _ => {}
        }
        let mut cursor = node.walk();
        let mut children: Vec<_> = node.named_children(&mut cursor).collect();
        children.reverse();
        for child in children {
            if child.start_byte() < before_byte {
                stack.push(child);
            }
        }
    }
}

fn java_type_from_node(
    java: &JavaAnalyzer,
    file: &ProjectFile,
    source: &str,
    type_node: Node<'_>,
) -> Option<CodeUnit> {
    java.resolve_type_name_in_file(
        file,
        normalize_java_type_text(java_node_text(type_node, source)),
    )
}

fn java_member_candidates(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    owner_fqn: &str,
    member: &str,
) -> DefinitionLookupOutcome {
    let mut candidates = support.fqn(&format!("{owner_fqn}.{member}"));
    sort_units(&mut candidates);
    candidates.dedup();
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }

    if let Some(owner) = analyzer.definitions(owner_fqn).next().cloned()
        && let Some(provider) = analyzer.type_hierarchy_provider()
    {
        let mut seen = HashSet::default();
        let mut level = provider.get_direct_ancestors(&owner);
        seen.insert(owner);
        while !level.is_empty() {
            let mut level_candidates = Vec::new();
            let mut next_level = Vec::new();
            for ancestor in level {
                if !seen.insert(ancestor.clone()) {
                    continue;
                }
                level_candidates.extend(support.fqn(&format!("{}.{}", ancestor.fq_name(), member)));
                next_level.extend(provider.get_direct_ancestors(&ancestor));
            }
            sort_units(&mut level_candidates);
            level_candidates.dedup();
            if !level_candidates.is_empty() {
                return candidates_outcome(level_candidates);
            }
            level = next_level;
        }
    }
    no_definition(
        "no_indexed_definition",
        format!("`{owner_fqn}.{member}` is not indexed as a Java definition"),
    )
}

fn java_static_import_candidates(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    member: &str,
) -> DefinitionLookupOutcome {
    let mut candidates = Vec::new();
    let mut saw_external = false;
    for import in analyzer.import_statements(file) {
        let Some(path) = java_static_import_path(import) else {
            continue;
        };
        if let Some(owner) = path.strip_suffix(".*") {
            let owner_candidates = support.fqn(&format!("{owner}.{member}"));
            if owner_candidates.is_empty() && !java_workspace_fqn_exists(support, owner) {
                saw_external = true;
            }
            candidates.extend(owner_candidates);
            continue;
        }
        let Some((owner, imported_member)) = path.rsplit_once('.') else {
            continue;
        };
        if imported_member != member {
            continue;
        }
        let imported = support.fqn(path);
        if imported.is_empty() && !java_workspace_fqn_exists(support, owner) {
            saw_external = true;
        }
        candidates.extend(imported);
    }
    sort_units(&mut candidates);
    candidates.dedup();
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }
    if saw_external {
        return boundary(format!(
            "`{member}` appears to cross a Java static import boundary not indexed in this workspace"
        ));
    }
    no_definition(
        "no_static_import_match",
        format!("`{member}` did not match an indexed Java static import"),
    )
}

fn java_import_boundary_for_type(
    java: &JavaAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    name: &str,
) -> bool {
    for import in java.import_statements(file) {
        let trimmed = import.trim();
        if trimmed.starts_with("import static ") {
            continue;
        }
        let Some(path) = trimmed
            .strip_prefix("import ")
            .and_then(|rest| rest.strip_suffix(';'))
            .map(str::trim)
        else {
            continue;
        };
        if let Some(package) = path.strip_suffix(".*") {
            if !package.is_empty() && !java_workspace_package_exists(support, package) {
                return true;
            }
            continue;
        }
        if path.rsplit('.').next() == Some(name) {
            let package = path
                .rsplit_once('.')
                .map(|(package, _)| package)
                .unwrap_or("");
            return !java_workspace_package_exists(support, package);
        }
    }
    false
}

fn java_static_import_path(import: &str) -> Option<&str> {
    import
        .trim()
        .strip_prefix("import static ")
        .and_then(|rest| rest.strip_suffix(';'))
        .map(str::trim)
}

fn java_workspace_fqn_exists(support: &DefinitionLookupIndex, fqn: &str) -> bool {
    support.fqn_exists(fqn)
}

fn java_workspace_package_exists(support: &DefinitionLookupIndex, package: &str) -> bool {
    support.package_exists(package) || support.fqn_prefix_exists(package)
}

fn java_node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or_default()
        .trim()
}

fn normalize_java_type_text(raw: &str) -> &str {
    raw.split('<')
        .next()
        .unwrap_or(raw)
        .trim()
        .trim_end_matches("[]")
        .trim()
}

fn resolve_php(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    let Some(php) = resolve_analyzer::<PhpAnalyzer>(analyzer) else {
        return no_definition("php_analyzer_unavailable", "PHP analyzer is unavailable");
    };
    let Some(tree) = tree else {
        return no_definition("php_parse_failed", "PHP source could not be parsed");
    };
    let root = tree.root_node();
    let Some(node) = smallest_named_node_covering(root, site.range.start_byte, site.range.end_byte)
    else {
        return no_definition(
            "no_indexed_definition",
            format!(
                "`{}` did not resolve to an indexed PHP definition",
                site.text
            ),
        );
    };
    if php_is_non_reference_context(node) || php_is_declaration_name(node) {
        return no_definition(
            "declaration_or_import_site",
            format!("`{}` is not a PHP reference site", site.text),
        );
    }
    if php_is_variable_reference(node) {
        return no_definition(
            "local_variable_reference",
            format!(
                "`{}` is a PHP variable reference, not an indexed definition",
                site.text
            ),
        );
    }

    let ctx = FileContext {
        namespace: php.namespace_of_file(file),
        aliases: parse_php_use_aliases_from_source(source),
    };
    let class_ranges = ClassRangeIndex::build(analyzer, file);
    match php_reference_node(node) {
        Some(PhpReferenceNode::Type(type_node)) => {
            let raw = php_qualified_candidate_text(type_node, source);
            php_fqn_outcome(support, resolve_php_type(&raw, &ctx), &raw)
        }
        Some(PhpReferenceNode::Function(name_node)) => {
            let raw = php_qualified_candidate_text(name_node, source);
            php_fqn_outcome(support, resolve_php_function(&raw, &ctx), &raw)
        }
        Some(PhpReferenceNode::Constant(name_node)) => {
            let raw = php_qualified_candidate_text(name_node, source);
            php_fqn_outcome(support, resolve_php_constant(&raw, &ctx), &raw)
        }
        Some(PhpReferenceNode::StaticMember { scope, name }) => {
            let member = php_node_text(name, source).trim_start_matches('$');
            let owner = php_static_scope_fqn(php, support, scope, source, &ctx, &class_ranges);
            php_member_outcome(php, analyzer, support, owner, member)
        }
        Some(PhpReferenceNode::InstanceMember { object, name }) => {
            let member = php_node_text(name, source).trim_start_matches('$');
            let bindings =
                php_bindings_before(php, file, source, root, site.range.start_byte, &ctx);
            let owner = php_instance_receiver_fqn(object, source, &class_ranges, &bindings);
            php_member_outcome(php, analyzer, support, owner, member)
        }
        None => no_definition(
            "unsupported_php_reference_shape",
            format!(
                "`{}` is a PHP `{}` reference shape that get_definition does not resolve yet",
                site.text,
                node.kind()
            ),
        ),
    }
}

fn resolve_csharp(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    let Some(csharp) = resolve_analyzer::<CSharpAnalyzer>(analyzer) else {
        return no_definition("csharp_analyzer_unavailable", "C# analyzer is unavailable");
    };
    let Some(tree) = tree else {
        return no_definition("csharp_parse_failed", "C# source could not be parsed");
    };
    let Some(node) =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)
    else {
        return no_definition(
            "no_indexed_definition",
            format!(
                "`{}` did not resolve to an indexed C# definition",
                site.text
            ),
        );
    };
    if csharp_is_declaration_name(node) {
        return no_definition(
            "declaration_or_import_site",
            format!("`{}` is not a C# reference site", site.text),
        );
    }

    match csharp_reference_node(node) {
        Some(CSharpReferenceNode::Type(type_node)) => {
            let reference = csharp_reference_type_text(type_node, source);
            csharp_type_outcome(csharp, support, file, &reference)
        }
        Some(CSharpReferenceNode::Member { receiver, name }) => {
            let member = csharp_member_name_text(name, source);
            if member.is_empty() {
                return no_definition("no_member_name", "C# member reference is blank");
            }
            let owners = csharp_receiver_type_units(
                analyzer,
                csharp,
                support,
                file,
                source,
                tree.root_node(),
                receiver,
            );
            let arity = csharp_invocation_arity(name, source);
            let outcome = csharp_member_outcome(analyzer, support, owners, member, arity);
            if outcome.status == DefinitionLookupStatus::NoDefinition {
                let extensions =
                    csharp_extension_method_candidates(csharp, analyzer, file, member, arity);
                if !extensions.is_empty() {
                    return candidates_outcome(extensions);
                }
            }
            outcome
        }
        Some(CSharpReferenceNode::UnqualifiedMember(name)) => {
            let member = csharp_member_name_text(name, source);
            let bindings = csharp_bindings_before_scoped(
                csharp,
                file,
                source,
                tree.root_node(),
                name.start_byte(),
            );
            if bindings.is_shadowed(member) {
                return no_definition(
                    "local_variable_reference",
                    format!("`{member}` is a local C# value or local function"),
                );
            }
            let owners = csharp_enclosing_class(analyzer, file, name.start_byte())
                .into_iter()
                .collect();
            let arity = csharp_invocation_arity(name, source);
            let outcome = csharp_member_outcome(analyzer, support, owners, member, arity);
            if outcome.status == DefinitionLookupStatus::NoDefinition
                && csharp_static_using_boundary_for_member(csharp, support, file)
            {
                return boundary(format!(
                    "`{member}` appears to cross a C# static using boundary not indexed in this workspace"
                ));
            }
            outcome
        }
        Some(CSharpReferenceNode::Identifier(identifier)) => {
            let text = csharp_node_text(identifier, source);
            if text.is_empty() {
                return no_definition("no_reference_text", "C# identifier is blank");
            }
            if csharp_is_type_reference_node(identifier) {
                let reference = csharp_reference_type_text(identifier, source);
                return csharp_type_outcome(csharp, support, file, &reference);
            }
            let bindings = csharp_bindings_before_scoped(
                csharp,
                file,
                source,
                tree.root_node(),
                identifier.start_byte(),
            );
            if !bindings.is_shadowed(text) {
                let outcome = csharp_type_outcome(csharp, support, file, text);
                if outcome.status != DefinitionLookupStatus::NoDefinition {
                    return outcome;
                }
            }
            no_definition(
                "no_indexed_definition",
                format!("`{text}` did not resolve to an indexed C# definition"),
            )
        }
        None => no_definition(
            "unsupported_csharp_reference_shape",
            format!(
                "`{}` is a C# `{}` reference shape that get_definition does not resolve yet",
                site.text,
                node.kind()
            ),
        ),
    }
}

fn parse_csharp_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
        .ok()?;
    parser.parse(source, None)
}

enum CSharpReferenceNode<'tree> {
    Type(Node<'tree>),
    Member {
        receiver: Node<'tree>,
        name: Node<'tree>,
    },
    UnqualifiedMember(Node<'tree>),
    Identifier(Node<'tree>),
}

fn csharp_reference_node(node: Node<'_>) -> Option<CSharpReferenceNode<'_>> {
    let original = node;
    let mut current = node;
    while let Some(parent) = current.parent() {
        if (matches!(parent.kind(), "generic_name" | "qualified_name")
            && parent.start_byte() <= current.start_byte()
            && parent.end_byte() >= current.end_byte())
            || (parent.kind() == "member_access_expression"
                && (csharp_member_access_name(parent) == Some(current)
                    || csharp_member_access_name(parent) == Some(original)))
        {
            current = parent;
        } else {
            break;
        }
    }

    match current.kind() {
        "member_access_expression" => Some(CSharpReferenceNode::Member {
            receiver: csharp_member_access_receiver(current)?,
            name: csharp_member_access_name(current)?,
        }),
        "object_creation_expression" => current
            .child_by_field_name("type")
            .or_else(|| csharp_first_type_child(current))
            .map(CSharpReferenceNode::Type),
        "identifier" | "type" => {
            if csharp_is_unqualified_invocation_target(current) {
                return Some(CSharpReferenceNode::UnqualifiedMember(current));
            }
            if csharp_is_type_reference_node(current) {
                Some(CSharpReferenceNode::Type(current))
            } else {
                Some(CSharpReferenceNode::Identifier(current))
            }
        }
        "qualified_name" | "generic_name" | "nullable_type" | "array_type" => {
            Some(CSharpReferenceNode::Type(current))
        }
        _ => None,
    }
}

fn csharp_is_unqualified_invocation_target(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "invocation_expression"
            && parent.child_by_field_name("function") == Some(node)
    })
}

fn csharp_invocation_arity(node: Node<'_>, source: &str) -> Option<usize> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if matches!(parent.kind(), "member_access_expression" | "qualified_name") {
            current = parent;
            continue;
        }
        if parent.kind() == "invocation_expression"
            && parent.child_by_field_name("function") == Some(current)
        {
            return Some(csharp_argument_count(parent, source));
        }
        break;
    }
    None
}

fn csharp_member_name_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    csharp_node_text(node, source)
        .split('<')
        .next()
        .unwrap_or_default()
        .trim()
}

fn csharp_type_outcome(
    csharp: &CSharpAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    reference: &str,
) -> DefinitionLookupOutcome {
    let mut candidates = csharp_visible_type_candidates(csharp, file, reference);
    if candidates.is_empty() {
        candidates = support.fqn(reference);
    }
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }
    if csharp_import_boundary_for_type(csharp, support, file, reference) {
        return boundary(format!(
            "`{reference}` appears to cross a C# using boundary not indexed in this workspace"
        ));
    }
    no_definition(
        "no_indexed_definition",
        format!("`{reference}` did not resolve to an indexed C# type"),
    )
}

fn csharp_member_outcome(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    owners: Vec<CodeUnit>,
    member: &str,
    arity: Option<usize>,
) -> DefinitionLookupOutcome {
    if owners.is_empty() {
        return no_definition(
            "unsupported_csharp_receiver",
            format!("receiver for C# member `{member}` is not resolved"),
        );
    };

    let mut direct_candidates = Vec::new();
    for owner in &owners {
        direct_candidates.extend(support.fqn(&format!("{}.{}", owner.fq_name(), member)));
    }
    sort_units(&mut direct_candidates);
    direct_candidates.dedup();
    let direct_candidates = csharp_filter_candidates_by_arity(direct_candidates, arity);
    if !direct_candidates.is_empty() {
        return candidates_outcome(direct_candidates);
    }

    if let Some(provider) = analyzer.type_hierarchy_provider() {
        let mut seen = HashSet::default();
        let mut level = Vec::new();
        for owner in owners {
            seen.insert(owner.clone());
            level.extend(provider.get_direct_ancestors(&owner));
        }
        while !level.is_empty() {
            let mut level_candidates = Vec::new();
            let mut next_level = Vec::new();
            for ancestor in level {
                if !seen.insert(ancestor.clone()) {
                    continue;
                }
                level_candidates.extend(support.fqn(&format!("{}.{}", ancestor.fq_name(), member)));
                next_level.extend(provider.get_direct_ancestors(&ancestor));
            }
            sort_units(&mut level_candidates);
            level_candidates.dedup();
            let level_candidates = csharp_filter_candidates_by_arity(level_candidates, arity);
            if !level_candidates.is_empty() {
                return candidates_outcome(level_candidates);
            }
            level = next_level;
        }
    }
    no_definition(
        "no_indexed_definition",
        format!("C# member `{member}` is not indexed as a definition"),
    )
}

fn csharp_filter_candidates_by_arity(
    candidates: Vec<CodeUnit>,
    arity: Option<usize>,
) -> Vec<CodeUnit> {
    let Some(expected) = arity else {
        return candidates;
    };
    let filtered: Vec<_> = candidates
        .iter()
        .filter(|unit| unit.is_function() && csharp_signature_arity(unit.signature()) == expected)
        .cloned()
        .collect();
    if filtered.is_empty() {
        candidates
    } else {
        filtered
    }
}

fn csharp_extension_method_candidates(
    csharp: &CSharpAnalyzer,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    member: &str,
    arity: Option<usize>,
) -> Vec<CodeUnit> {
    let mut namespaces = csharp.using_namespaces_of(file);
    let file_namespace = csharp.namespace_of_file(file);
    if !file_namespace.is_empty() {
        namespaces.push(file_namespace);
    }
    namespaces.sort();
    namespaces.dedup();

    let mut candidates: Vec<_> = csharp
        .get_all_declarations()
        .into_iter()
        .filter(|unit| unit.is_function() && unit.identifier() == member)
        .filter(|unit| csharp_extension_declaring_type_is_visible(csharp, &namespaces, unit))
        .filter(|unit| csharp_is_extension_method(analyzer, unit))
        .collect();
    sort_units(&mut candidates);
    candidates.dedup();

    if let Some(call_arity) = arity {
        let expected = call_arity + 1;
        let exact: Vec<_> = candidates
            .iter()
            .filter(|unit| csharp_signature_arity(unit.signature()) == expected)
            .cloned()
            .collect();
        if !exact.is_empty() {
            return exact;
        }
    }

    candidates
}

fn csharp_extension_declaring_type_is_visible(
    analyzer: &dyn IAnalyzer,
    namespaces: &[String],
    unit: &CodeUnit,
) -> bool {
    analyzer.parent_of(unit).is_some_and(|owner| {
        namespaces
            .iter()
            .any(|namespace| owner.package_name() == namespace)
    })
}

fn csharp_is_extension_method(analyzer: &dyn IAnalyzer, unit: &CodeUnit) -> bool {
    analyzer.signatures_of(unit).iter().any(|signature| {
        signature
            .split_once('(')
            .map(|(_, parameters)| parameters.trim_start().starts_with("this "))
            .unwrap_or(false)
    })
}

fn csharp_receiver_type_units(
    analyzer: &dyn IAnalyzer,
    csharp: &CSharpAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    receiver: Node<'_>,
) -> Vec<CodeUnit> {
    match receiver.kind() {
        "identifier" => {
            let name = csharp_node_text(receiver, source);
            let bindings =
                csharp_bindings_before_scoped(csharp, file, source, root, receiver.start_byte());
            if let Some(fqn) = first_precise(&bindings, name) {
                return support.fqn(&fqn);
            }
            if bindings.is_shadowed(name) {
                Vec::new()
            } else {
                let mut candidates = csharp_enclosing_member_type_units(
                    analyzer, csharp, support, file, receiver, name,
                );
                if candidates.is_empty() {
                    candidates = csharp_visible_type_candidates(csharp, file, name);
                }
                candidates
            }
        }
        "this" => csharp_enclosing_class(analyzer, file, receiver.start_byte())
            .into_iter()
            .collect(),
        "base" => csharp_enclosing_class(analyzer, file, receiver.start_byte())
            .and_then(|owner| {
                analyzer
                    .type_hierarchy_provider()
                    .and_then(|provider| provider.get_ancestors(&owner).into_iter().next())
            })
            .into_iter()
            .collect(),
        "qualified_name" | "generic_name" => {
            csharp_visible_type_candidates(csharp, file, csharp_node_text(receiver, source))
        }
        _ => Vec::new(),
    }
}

fn csharp_enclosing_member_type_units(
    analyzer: &dyn IAnalyzer,
    csharp: &CSharpAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    receiver: Node<'_>,
    name: &str,
) -> Vec<CodeUnit> {
    let Some(owner) = csharp_enclosing_class(analyzer, file, receiver.start_byte()) else {
        return Vec::new();
    };
    let mut candidates = Vec::new();
    csharp_collect_member_type_units(csharp, support, file, &owner, name, &mut candidates);
    if let Some(provider) = analyzer.type_hierarchy_provider() {
        for ancestor in provider.get_ancestors(&owner) {
            csharp_collect_member_type_units(
                csharp,
                support,
                file,
                &ancestor,
                name,
                &mut candidates,
            );
        }
    }
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn csharp_collect_member_type_units(
    csharp: &CSharpAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    owner: &CodeUnit,
    name: &str,
    candidates: &mut Vec<CodeUnit>,
) {
    if let Some(type_fqn) = csharp_member_declared_type_fq_name(csharp, file, owner, name) {
        candidates.extend(support.fqn(&type_fqn));
    }
}

fn csharp_visible_type_candidates(
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    name: &str,
) -> Vec<CodeUnit> {
    let mut candidates = csharp.visible_type_candidates(file, name);
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn csharp_enclosing_class(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    byte: usize,
) -> Option<CodeUnit> {
    let fqn = ClassRangeIndex::build(analyzer, file)
        .enclosing(byte)?
        .to_string();
    analyzer.definitions(&fqn).next().cloned()
}

fn csharp_import_boundary_for_type(
    csharp: &CSharpAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    reference: &str,
) -> bool {
    if csharp_alias_using_boundary_for_type(csharp, support, file, reference) {
        return true;
    }
    let simple = reference.rsplit('.').next().unwrap_or(reference);
    csharp
        .using_namespaces_of(file)
        .into_iter()
        .any(|namespace| {
            !csharp_workspace_namespace_exists(support, &namespace)
                && (reference == simple || reference.starts_with(&format!("{namespace}.")))
        })
}

fn csharp_workspace_namespace_exists(support: &DefinitionLookupIndex, namespace: &str) -> bool {
    support.package_exists(namespace)
}

fn csharp_alias_using_boundary_for_type(
    csharp: &CSharpAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    reference: &str,
) -> bool {
    for raw in csharp.import_statements(file) {
        let trimmed = raw
            .trim()
            .trim_start_matches("global ")
            .trim_start_matches("using ")
            .trim_end_matches(';')
            .trim();
        let Some((alias, target)) = trimmed.split_once('=') else {
            continue;
        };
        if alias.trim() == reference && !csharp_workspace_type_exists(support, target.trim()) {
            return true;
        }
    }
    false
}

fn csharp_static_using_boundary_for_member(
    csharp: &CSharpAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
) -> bool {
    csharp.import_statements(file).iter().any(|raw| {
        raw.trim()
            .trim_start_matches("global ")
            .trim_start_matches("using ")
            .trim_end_matches(';')
            .trim()
            .strip_prefix("static ")
            .is_some_and(|target| !csharp_workspace_type_exists(support, target.trim()))
    })
}

fn csharp_workspace_type_exists(support: &DefinitionLookupIndex, reference: &str) -> bool {
    support.fqn_exists(reference) || support.normalized_fqn_exists(reference)
}

const CSHARP_SCOPE_NODES: &[&str] = &[
    "method_declaration",
    "constructor_declaration",
    "destructor_declaration",
    "operator_declaration",
    "accessor_declaration",
    "local_function_statement",
    "lambda_expression",
    "block",
    "for_statement",
    "for_each_statement",
    "using_statement",
    "catch_clause",
];

fn csharp_bindings_before_scoped(
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    cutoff_start: usize,
) -> LocalInferenceEngine<String> {
    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    csharp_seed_active_path(root, cutoff_start, csharp, file, source, &mut bindings);
    bindings
}

fn csharp_seed_active_path(
    node: Node<'_>,
    cutoff_start: usize,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<String>,
) {
    if node.start_byte() >= cutoff_start {
        return;
    }

    if node.kind() == "local_function_statement"
        && let Some(name) = node.child_by_field_name("name")
        && name.start_byte() < cutoff_start
    {
        bindings.declare_shadow(csharp_node_text(name, source));
    }

    let enters_scope = CSHARP_SCOPE_NODES.contains(&node.kind());
    if enters_scope && !(node.start_byte() <= cutoff_start && cutoff_start < node.end_byte()) {
        return;
    }
    if enters_scope {
        bindings.enter_scope();
    }

    if matches!(node.kind(), "parameter" | "variable_declaration")
        && node.end_byte() <= cutoff_start
    {
        seed_csharp_bindings_before(node, cutoff_start, csharp, file, source, bindings);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.start_byte() >= cutoff_start {
            break;
        }
        csharp_seed_active_path(child, cutoff_start, csharp, file, source, bindings);
    }
}

fn resolve_python(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    let Some(py) = resolve_analyzer::<PythonAnalyzer>(analyzer) else {
        return no_definition(
            "python_analyzer_unavailable",
            "Python analyzer is unavailable",
        );
    };
    let Some(tree) = tree else {
        return no_definition("python_parse_failed", "Python source could not be parsed");
    };
    let Some(node) =
        smallest_named_node_covering(tree.root_node(), site.focus_start_byte, site.focus_end_byte)
    else {
        return no_definition(
            "no_indexed_definition",
            format!(
                "`{}` did not resolve to an indexed Python definition",
                site.text
            ),
        );
    };
    if python_is_non_reference_context(node) || python_is_declaration_identifier(node) {
        return no_definition(
            "declaration_or_import_site",
            format!("`{}` is not a Python reference site", site.text),
        );
    }

    let ctx = PythonDefinitionContext::build(py, analyzer, support, file, source);
    let reference = python_reference_node(node);
    match reference {
        Some(PythonReferenceNode::Attribute { object, attribute }) => {
            let object_text = python_slice(object, source);
            let attribute_text = python_slice(attribute, source);
            if object_text.is_empty() || attribute_text.is_empty() {
                return no_definition("no_reference_text", "Python attribute reference is blank");
            }
            let object_shadowed = python_name_shadowed_at(
                object_text,
                tree.root_node(),
                site.range.start_byte,
                source,
            );
            if !object_shadowed && let Some(module) = ctx.namespace_module_for_object(object_text) {
                return python_fqn_outcome(
                    support,
                    &format!("{module}.{attribute_text}"),
                    site.text.as_str(),
                );
            }
            if let Some(receiver_type) =
                python_receiver_type_unit(analyzer, py, file, source, tree.root_node(), object)
            {
                return python_member_outcome(analyzer, support, receiver_type, attribute_text);
            }
            if object_shadowed {
                return no_definition(
                    "local_variable_reference",
                    format!("`{object_text}` is a local Python value"),
                );
            }
            if python_unresolved_import_boundary(file, analyzer, object_text, Some(attribute_text))
            {
                return boundary(format!(
                    "`{object_text}.{attribute_text}` crosses a Python import boundary not indexed in this workspace"
                ));
            }
            no_definition(
                "no_indexed_definition",
                format!(
                    "`{}` did not resolve to an indexed Python definition",
                    site.text
                ),
            )
        }
        Some(PythonReferenceNode::Identifier(identifier)) => {
            let text = python_slice(identifier, source);
            if text.is_empty() {
                return no_definition("no_reference_text", "Python identifier is blank");
            }
            if python_name_shadowed_at(text, tree.root_node(), site.range.start_byte, source) {
                return no_definition(
                    "local_variable_reference",
                    format!("`{text}` is a local Python value"),
                );
            }
            if let Some(fqn) = ctx.named.get(text).or_else(|| ctx.namespace.get(text)) {
                return python_fqn_outcome(support, fqn, text);
            }
            if let Some(candidates) = ctx.same_file.get(text)
                && !candidates.is_empty()
            {
                return candidates_outcome(candidates.clone());
            }
            if python_unresolved_import_boundary(file, analyzer, text, None) {
                return boundary(format!(
                    "`{text}` crosses a Python import boundary not indexed in this workspace"
                ));
            }
            no_definition(
                "no_indexed_definition",
                format!("`{text}` did not resolve to an indexed Python definition"),
            )
        }
        None => no_definition(
            "unsupported_python_reference_shape",
            format!(
                "`{}` is a Python `{}` reference shape that get_definition does not resolve yet",
                site.text,
                node.kind()
            ),
        ),
    }
}

fn parse_python_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .ok()?;
    parser.parse(source, None)
}

struct PythonDefinitionContext {
    named: HashMap<String, String>,
    namespace: HashMap<String, String>,
    same_file: HashMap<String, Vec<CodeUnit>>,
}

impl PythonDefinitionContext {
    fn build(
        py: &PythonAnalyzer,
        analyzer: &dyn IAnalyzer,
        _support: &DefinitionLookupIndex,
        file: &ProjectFile,
        _source: &str,
    ) -> Self {
        let binder = py.import_binder_of(file);
        let mut named = HashMap::default();
        let mut namespace = HashMap::default();
        for (local, binding) in &binder.bindings {
            match binding.kind {
                ImportKind::Named => {
                    if let Some(imported) = &binding.imported_name {
                        named.insert(
                            local.clone(),
                            format!("{}.{}", binding.module_specifier, imported),
                        );
                    }
                }
                ImportKind::Namespace => {
                    namespace.insert(local.clone(), binding.module_specifier.clone());
                }
                ImportKind::Default | ImportKind::CommonJsRequire | ImportKind::Glob => {}
            }
        }
        let mut same_file: HashMap<String, Vec<CodeUnit>> = HashMap::default();
        for unit in analyzer.declarations(file) {
            same_file
                .entry(unit.identifier().to_string())
                .or_default()
                .push(unit.clone());
        }
        for units in same_file.values_mut() {
            sort_units(units);
        }
        Self {
            named,
            namespace,
            same_file,
        }
    }

    fn namespace_module_for_object(&self, object: &str) -> Option<&str> {
        if let Some(module) = self.namespace.get(object) {
            return Some(module.as_str());
        }
        self.namespace
            .values()
            .find(|module| module.as_str() == object)
            .map(String::as_str)
    }
}

enum PythonReferenceNode<'tree> {
    Identifier(Node<'tree>),
    Attribute {
        object: Node<'tree>,
        attribute: Node<'tree>,
    },
}

fn python_reference_node(node: Node<'_>) -> Option<PythonReferenceNode<'_>> {
    let original = node;
    let mut node = node;
    while let Some(parent) = node.parent() {
        if parent.kind() == "attribute" {
            if parent.child_by_field_name("attribute") == Some(node)
                || parent.child_by_field_name("attribute") == Some(original)
            {
                node = parent;
            } else {
                break;
            }
        } else {
            break;
        }
    }
    match node.kind() {
        "attribute" => {
            let object = node.child_by_field_name("object")?;
            let attribute = node.child_by_field_name("attribute")?;
            Some(PythonReferenceNode::Attribute { object, attribute })
        }
        "identifier" => Some(PythonReferenceNode::Identifier(node)),
        _ => None,
    }
}

fn python_fqn_outcome(
    support: &DefinitionLookupIndex,
    fqn: &str,
    raw: &str,
) -> DefinitionLookupOutcome {
    let candidates = support.fqn(fqn);
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }
    if python_crosses_unindexed_boundary(support, fqn) {
        return boundary(format!(
            "`{raw}` resolves to `{fqn}`, which is outside this partial Python workspace analysis"
        ));
    }
    no_definition(
        "no_indexed_definition",
        format!("`{raw}` resolved to `{fqn}`, but no indexed Python definition was found"),
    )
}

fn python_member_outcome(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    receiver_type: CodeUnit,
    member: &str,
) -> DefinitionLookupOutcome {
    let mut candidates = support.fqn(&format!("{}.{}", receiver_type.fq_name(), member));
    if candidates.is_empty()
        && let Some(provider) = analyzer.type_hierarchy_provider()
    {
        for ancestor in provider.get_ancestors(&receiver_type) {
            candidates.extend(support.fqn(&format!("{}.{}", ancestor.fq_name(), member)));
        }
        sort_units(&mut candidates);
        candidates.dedup();
    }
    if candidates.is_empty() {
        no_definition(
            "no_indexed_definition",
            format!(
                "`{}.{member}` is not indexed as a Python definition",
                receiver_type.fq_name()
            ),
        )
    } else {
        candidates_outcome(candidates)
    }
}

fn python_crosses_unindexed_boundary(support: &DefinitionLookupIndex, fqn: &str) -> bool {
    let Some((module, _)) = fqn.rsplit_once('.') else {
        return !python_workspace_module_exists(support, "");
    };
    !python_workspace_module_exists(support, module)
}

fn python_workspace_module_exists(support: &DefinitionLookupIndex, module: &str) -> bool {
    support.package_exists(module) || support.fqn_exists(module)
}

fn python_receiver_type_unit(
    analyzer: &dyn IAnalyzer,
    py: &PythonAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    object: Node<'_>,
) -> Option<CodeUnit> {
    if object.kind() != "identifier" {
        return None;
    }
    let receiver = python_slice(object, source);
    if let Some(unit) = python_self_receiver_type(analyzer, py, file, root, object, receiver) {
        return Some(unit);
    }
    let facts_by_scope = collect_scope_facts(analyzer, file, &[], "", true);
    let facts = enclosing_scope_facts(analyzer, file, &facts_by_scope, object)?;
    let raw_type = facts
        .resolution_for(receiver)
        .as_precise()
        .and_then(|targets| targets.iter().next().cloned())?;
    resolve_python_receiver_type(analyzer, file, &raw_type, false)
}

fn python_self_receiver_type(
    analyzer: &dyn IAnalyzer,
    _py: &PythonAnalyzer,
    file: &ProjectFile,
    _root: Node<'_>,
    object: Node<'_>,
    receiver: &str,
) -> Option<CodeUnit> {
    if receiver != "self" && receiver != "cls" {
        return None;
    }
    let range = Range {
        start_byte: object.start_byte(),
        end_byte: object.end_byte(),
        start_line: 0,
        end_line: 0,
    };
    analyzer
        .enclosing_code_unit(file, &range)
        .and_then(|enclosing| analyzer.parent_of(&enclosing).or(Some(enclosing)))
        .filter(|unit| unit.is_class())
}

fn python_unresolved_import_boundary(
    file: &ProjectFile,
    analyzer: &dyn IAnalyzer,
    local: &str,
    attribute: Option<&str>,
) -> bool {
    let Some(provider) = analyzer.import_analysis_provider() else {
        return false;
    };
    for import in provider.import_info_of(file) {
        let alias_or_identifier = import.alias.as_deref().or(import.identifier.as_deref());
        if alias_or_identifier == Some(local) {
            return provider
                .imported_code_units_of(file)
                .into_iter()
                .all(|unit| unit.identifier() != local);
        }
        if let Some(attribute) = attribute
            && import.identifier.as_deref() == Some(attribute)
            && import.alias.as_deref().unwrap_or(attribute) == attribute
        {
            return provider
                .imported_code_units_of(file)
                .into_iter()
                .all(|unit| unit.identifier() != attribute);
        }
    }
    false
}

fn python_name_shadowed_at(name: &str, root: Node<'_>, byte: usize, source: &str) -> bool {
    let Some(scope) = python_enclosing_function(root, byte) else {
        return false;
    };
    let mut locals = HashSet::default();
    if let Some(parameters) = scope.child_by_field_name("parameters") {
        python_collect_parameter_names(parameters, source, &mut locals);
    }
    if let Some(body) = scope.child_by_field_name("body") {
        python_collect_bound_targets(body, source, &mut locals);
    }
    locals.contains(name)
}

fn python_enclosing_function<'tree>(root: Node<'tree>, byte: usize) -> Option<Node<'tree>> {
    let mut best = None;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.start_byte() <= byte && byte < node.end_byte() {
            if matches!(node.kind(), "function_definition" | "lambda") {
                best = Some(node);
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                stack.push(child);
            }
        }
    }
    best
}

fn python_collect_parameter_names(params: Node<'_>, source: &str, out: &mut HashSet<String>) {
    let mut cursor = params.walk();
    for child in params.named_children(&mut cursor) {
        let name = match child.kind() {
            "identifier" => Some(child),
            _ => child.child_by_field_name("name").or_else(|| {
                child
                    .named_child(0)
                    .filter(|node| node.kind() == "identifier")
            }),
        };
        if let Some(name) = name {
            let text = python_slice(name, source).trim();
            if !text.is_empty() {
                out.insert(text.to_string());
            }
        }
    }
}

fn python_collect_bound_targets(node: Node<'_>, source: &str, out: &mut HashSet<String>) {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "function_definition" | "class_definition" => {
                if let Some(name) = node.child_by_field_name("name") {
                    let text = python_slice(name, source).trim();
                    if !text.is_empty() {
                        out.insert(text.to_string());
                    }
                }
                continue;
            }
            "lambda" => continue,
            "assignment" | "augmented_assignment" | "for_statement" | "for_in_clause" => {
                if let Some(left) = node.child_by_field_name("left") {
                    collect_assigned_identifiers(left, source, out);
                }
            }
            "named_expression" => {
                if let Some(name) = node.child_by_field_name("name") {
                    collect_assigned_identifiers(name, source, out);
                }
            }
            _ => {}
        }
        let mut cursor = node.walk();
        let mut children: Vec<_> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
    }
}

fn python_is_non_reference_context(node: Node<'_>) -> bool {
    let mut parent = Some(node);
    while let Some(current) = parent {
        if matches!(
            current.kind(),
            "import_statement"
                | "import_from_statement"
                | "comment"
                | "string"
                | "string_content"
                | "module"
        ) && current.kind() != "module"
        {
            return true;
        }
        parent = current.parent();
    }
    false
}

fn parse_php_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
        .ok()?;
    parser.parse(source, None)
}

enum PhpReferenceNode<'tree> {
    Type(Node<'tree>),
    Function(Node<'tree>),
    Constant(Node<'tree>),
    StaticMember {
        scope: Node<'tree>,
        name: Node<'tree>,
    },
    InstanceMember {
        object: Node<'tree>,
        name: Node<'tree>,
    },
}

fn php_reference_node<'tree>(node: Node<'tree>) -> Option<PhpReferenceNode<'tree>> {
    let node = php_qualified_reference_node(node);
    match node.kind() {
        "object_creation_expression" => php_object_creation_type(node).map(PhpReferenceNode::Type),
        "named_type" => (!php_is_in_object_creation(node)).then_some(PhpReferenceNode::Type(node)),
        "function_call_expression" => node
            .child_by_field_name("function")
            .filter(|name| matches!(name.kind(), "name" | "qualified_name"))
            .map(PhpReferenceNode::Function),
        "scoped_call_expression" | "class_constant_access_expression" => {
            let (scope, name) = php_static_member_parts(node)?;
            Some(PhpReferenceNode::StaticMember { scope, name })
        }
        "member_call_expression" | "member_access_expression" => {
            let object = node.child_by_field_name("object")?;
            let name = node.child_by_field_name("name")?;
            Some(PhpReferenceNode::InstanceMember { object, name })
        }
        "name" | "qualified_name" => {
            let parent = node.parent()?;
            match parent.kind() {
                "object_creation_expression" | "named_type" => Some(PhpReferenceNode::Type(node)),
                "function_call_expression"
                    if parent.child_by_field_name("function") == Some(node) =>
                {
                    Some(PhpReferenceNode::Function(node))
                }
                "scoped_call_expression" | "class_constant_access_expression"
                    if php_static_member_name(parent) == Some(node) =>
                {
                    let (scope, _) = php_static_member_parts(parent)?;
                    Some(PhpReferenceNode::StaticMember { scope, name: node })
                }
                "member_call_expression" | "member_access_expression"
                    if parent.child_by_field_name("name") == Some(node) =>
                {
                    let object = parent.child_by_field_name("object")?;
                    Some(PhpReferenceNode::InstanceMember { object, name: node })
                }
                _ if php_is_instanceof_type_name(node) => Some(PhpReferenceNode::Type(node)),
                _ if php_is_bare_constant_reference(node) => Some(PhpReferenceNode::Constant(node)),
                _ => None,
            }
        }
        _ => {
            let parent = node.parent()?;
            php_reference_node(parent)
        }
    }
}

/// True when `node` is the type operand of a PHP `instanceof`. The grammar models
/// `$x instanceof Foo` as a `binary_expression` whose `operator` child is the
/// `instanceof` token and whose `right` field is the class name.
fn php_is_instanceof_type_name(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    parent.kind() == "binary_expression"
        && parent
            .child_by_field_name("operator")
            .is_some_and(|operator| operator.kind() == "instanceof")
        && parent.child_by_field_name("right").is_some_and(|right| {
            right.start_byte() <= node.start_byte() && node.end_byte() <= right.end_byte()
        })
}

fn php_static_member_parts(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    let scope = node
        .child_by_field_name("scope")
        .or_else(|| node.child_by_field_name("class"))
        .or_else(|| node.named_child(0))?;
    let name = node
        .child_by_field_name("name")
        .or_else(|| node.child_by_field_name("constant"))
        .or_else(|| node.named_child(1))?;
    Some((scope, name))
}

fn php_static_member_name(node: Node<'_>) -> Option<Node<'_>> {
    php_static_member_parts(node).map(|(_, name)| name)
}

fn php_qualified_reference_node(mut node: Node<'_>) -> Node<'_> {
    while let Some(parent) = node.parent() {
        if matches!(parent.kind(), "namespace_name" | "qualified_name") {
            node = parent;
        } else {
            break;
        }
    }
    node
}

fn php_fqn_outcome(
    support: &DefinitionLookupIndex,
    fqn: Option<String>,
    raw: &str,
) -> DefinitionLookupOutcome {
    let Some(fqn) = fqn else {
        return no_definition(
            "no_indexed_definition",
            format!("`{raw}` did not resolve to a PHP definition name"),
        );
    };
    let candidates = support.fqn(&fqn);
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }
    if php_crosses_unindexed_boundary(support, &fqn) {
        return boundary(format!(
            "`{raw}` resolves to `{fqn}`, which is outside this partial PHP workspace analysis"
        ));
    }
    no_definition(
        "no_indexed_definition",
        format!("`{raw}` resolved to `{fqn}`, but no indexed PHP definition was found"),
    )
}

fn php_member_outcome(
    php: &PhpAnalyzer,
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    owner: Option<String>,
    member: &str,
) -> DefinitionLookupOutcome {
    let Some(owner) = owner else {
        return no_definition(
            "unsupported_php_receiver",
            format!("receiver for PHP member `{member}` is not resolved"),
        );
    };
    let fqn = format!("{owner}.{member}");
    let candidates = support.fqn(&fqn);
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }
    let inherited = php_inherited_member_candidates(php, analyzer, support, &owner, member);
    if !inherited.is_empty() {
        return candidates_outcome(inherited);
    }
    if php_crosses_unindexed_boundary(support, &owner) {
        return boundary(format!(
            "`{member}` appears to cross a PHP boundary at `{owner}` not indexed in this workspace"
        ));
    }
    no_definition(
        "no_indexed_definition",
        format!("`{fqn}` is not indexed as a PHP definition"),
    )
}

fn php_inherited_member_candidates(
    php: &PhpAnalyzer,
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    owner_fqn: &str,
    member: &str,
) -> Vec<CodeUnit> {
    let mut seen = HashSet::default();
    let mut level = php_direct_parent_fqns(php, analyzer, support, owner_fqn);
    seen.insert(owner_fqn.to_string());
    while !level.is_empty() {
        let mut level_candidates = Vec::new();
        let mut next_level = Vec::new();
        for ancestor in level {
            if !seen.insert(ancestor.clone()) {
                continue;
            }
            level_candidates.extend(support.fqn(&format!("{ancestor}.{member}")));
            next_level.extend(php_direct_parent_fqns(php, analyzer, support, &ancestor));
        }
        sort_units(&mut level_candidates);
        level_candidates.dedup();
        if !level_candidates.is_empty() {
            return level_candidates;
        }
        level = next_level;
    }
    Vec::new()
}

fn php_direct_parent_fqns(
    php: &PhpAnalyzer,
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    owner_fqn: &str,
) -> Vec<String> {
    php_parent_fqn(php, support, owner_fqn)
        .into_iter()
        .filter(|parent| analyzer.definitions(parent).next().is_some())
        .collect()
}

fn php_crosses_unindexed_boundary(support: &DefinitionLookupIndex, fqn: &str) -> bool {
    let Some((namespace, _)) = fqn.rsplit_once('.') else {
        return !php_workspace_exact_namespace_exists(support, "");
    };
    !php_workspace_exact_namespace_exists(support, namespace)
}

fn php_workspace_exact_namespace_exists(support: &DefinitionLookupIndex, namespace: &str) -> bool {
    support.package_exists(namespace)
}

fn php_static_scope_fqn(
    php: &PhpAnalyzer,
    support: &DefinitionLookupIndex,
    scope: Node<'_>,
    source: &str,
    ctx: &FileContext,
    class_ranges: &ClassRangeIndex,
) -> Option<String> {
    let text = php_node_text(scope, source);
    match text {
        "self" | "static" => class_ranges
            .enclosing(scope.start_byte())
            .map(str::to_string),
        "parent" => php_parent_fqn(php, support, class_ranges.enclosing(scope.start_byte())?),
        _ => resolve_php_type(text, ctx),
    }
}

fn php_parent_fqn(
    php: &PhpAnalyzer,
    support: &DefinitionLookupIndex,
    enclosing_fqn: &str,
) -> Option<String> {
    let child = support.fqn(enclosing_fqn).into_iter().next()?;
    let source = child.source();
    let raw_source = source.read_to_string().ok()?;
    let tree = parse_php_tree(&raw_source)?;
    let ctx = FileContext {
        namespace: php.namespace_of_file(source),
        aliases: parse_php_use_aliases_from_source(&raw_source),
    };
    let ranges = php.ranges(&child);
    let class_range = ranges.first()?;
    php_declared_parent_type(
        tree.root_node(),
        &raw_source,
        &ctx,
        class_range.start_byte,
        class_range.end_byte,
    )
}

fn php_declared_parent_type(
    mut node: Node<'_>,
    source: &str,
    ctx: &FileContext,
    start: usize,
    end: usize,
) -> Option<String> {
    loop {
        if node.start_byte() <= start
            && node.end_byte() >= end
            && matches!(
                node.kind(),
                "class_declaration" | "interface_declaration" | "trait_declaration"
            )
        {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if matches!(child.kind(), "base_clause" | "class_interface_clause") {
                    let mut clause_cursor = child.walk();
                    for clause_child in child.named_children(&mut clause_cursor) {
                        if matches!(
                            clause_child.kind(),
                            "name" | "qualified_name" | "namespace_name"
                        ) {
                            return resolve_php_type(
                                &php_qualified_candidate_text(clause_child, source),
                                ctx,
                            );
                        }
                    }
                }
            }
        }
        let mut cursor = node.walk();
        let mut next = None;
        for child in node.named_children(&mut cursor) {
            if child.start_byte() <= start && child.end_byte() >= end {
                next = Some(child);
                break;
            }
        }
        match next {
            Some(child) => node = child,
            None => return None,
        }
    }
}

fn php_instance_receiver_fqn(
    object: Node<'_>,
    source: &str,
    class_ranges: &ClassRangeIndex,
    bindings: &LocalInferenceEngine<String>,
) -> Option<String> {
    match object.kind() {
        "variable_name" => {
            let name = php_variable_identifier(object, source);
            if name == "this" {
                return class_ranges
                    .enclosing(object.start_byte())
                    .map(str::to_string);
            }
            first_precise(bindings, name)
        }
        _ => None,
    }
}

fn php_bindings_before(
    php: &PhpAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    byte: usize,
    ctx: &FileContext,
) -> LocalInferenceEngine<String> {
    let scope = php_enclosing_scope(root, byte).unwrap_or(root);
    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    let mut stack = vec![scope];
    while let Some(node) = stack.pop() {
        if node.start_byte() >= byte {
            continue;
        }
        if node != scope && PHP_SCOPE_NODES.contains(&node.kind()) {
            continue;
        }
        php_seed_parameters(node, source, ctx, &mut bindings);
        if node.end_byte() <= byte {
            php_seed_assignment(php, file, node, source, ctx, &mut bindings);
        }
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        for child in children.into_iter().rev() {
            if child.start_byte() < byte {
                stack.push(child);
            }
        }
    }
    bindings
}

const PHP_SCOPE_NODES: &[&str] = &[
    "function_definition",
    "method_declaration",
    "anonymous_function",
    "arrow_function",
];

fn php_enclosing_scope<'tree>(root: Node<'tree>, byte: usize) -> Option<Node<'tree>> {
    let mut best = None;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.start_byte() <= byte && byte < node.end_byte() {
            if PHP_SCOPE_NODES.contains(&node.kind()) {
                best = Some(node);
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                stack.push(child);
            }
        }
    }
    best
}

fn php_seed_parameters(
    node: Node<'_>,
    source: &str,
    ctx: &FileContext,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let Some(parameters) = node.child_by_field_name("parameters") else {
        return;
    };
    let mut cursor = parameters.walk();
    for child in parameters.named_children(&mut cursor) {
        if !matches!(
            child.kind(),
            "simple_parameter" | "property_promotion_parameter"
        ) {
            continue;
        }
        let Some(name_node) = child.child_by_field_name("name") else {
            continue;
        };
        let name = php_variable_identifier(name_node, source);
        if name.is_empty() {
            continue;
        }
        match child
            .child_by_field_name("type")
            .and_then(|type_node| resolve_php_type(php_node_text(type_node, source), ctx))
        {
            Some(fqn) => bindings.seed_symbol(name.to_string(), fqn),
            None => bindings.declare_shadow(name.to_string()),
        }
    }
}

fn php_seed_assignment(
    _php: &PhpAnalyzer,
    _file: &ProjectFile,
    node: Node<'_>,
    source: &str,
    ctx: &FileContext,
    bindings: &mut LocalInferenceEngine<String>,
) {
    if node.kind() != "assignment_expression" {
        return;
    }
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return;
    };
    if left.kind() != "variable_name" {
        return;
    }
    let name = php_variable_identifier(left, source);
    if name.is_empty() {
        return;
    }
    let resolved = (right.kind() == "object_creation_expression")
        .then(|| php_object_creation_type(right))
        .flatten()
        .and_then(|type_node| resolve_php_type(php_node_text(type_node, source), ctx));
    match resolved {
        Some(fqn) => bindings.seed_symbol(name.to_string(), fqn),
        None => bindings.declare_shadow(name.to_string()),
    }
}

fn php_object_creation_type(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| matches!(child.kind(), "name" | "qualified_name"))
}

fn php_is_in_object_creation(node: Node<'_>) -> bool {
    node.parent()
        .is_some_and(|parent| parent.kind() == "object_creation_expression")
}

fn php_is_bare_constant_reference(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    !matches!(
        parent.kind(),
        "function_call_expression"
            | "member_access_expression"
            | "member_call_expression"
            | "scoped_call_expression"
            | "class_constant_access_expression"
            | "named_type"
            | "object_creation_expression"
            | "function_definition"
            | "method_declaration"
            | "const_element"
            | "namespace_use_clause"
            | "namespace_definition"
            | "class_declaration"
            | "interface_declaration"
            | "trait_declaration"
            | "qualified_name"
            | "base_clause"
            | "class_interface_clause"
    )
}

fn php_variable_identifier<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    php_node_text(node, source).trim_start_matches('$')
}

fn php_is_declaration_name(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    parent.child_by_field_name("name") == Some(node)
        && matches!(
            parent.kind(),
            "class_declaration"
                | "interface_declaration"
                | "trait_declaration"
                | "function_definition"
                | "method_declaration"
                | "const_element"
                | "property_element"
                | "simple_parameter"
                | "property_promotion_parameter"
        )
}

fn php_is_variable_reference(node: Node<'_>) -> bool {
    let mut current = Some(node);
    while let Some(candidate) = current {
        if candidate.kind() == "variable_name" {
            return true;
        }
        current = candidate.parent();
    }
    false
}

fn php_is_non_reference_context(node: Node<'_>) -> bool {
    let mut parent = Some(node);
    while let Some(current) = parent {
        if matches!(
            current.kind(),
            "namespace_use_declaration"
                | "namespace_use_clause"
                | "comment"
                | "string"
                | "encapsed_string"
                | "string_value"
                | "heredoc"
                | "nowdoc"
        ) {
            return true;
        }
        parent = current.parent();
    }
    false
}

fn candidates_outcome(mut candidates: Vec<CodeUnit>) -> DefinitionLookupOutcome {
    sort_units(&mut candidates);
    candidates.dedup();
    let mut semantic_keys = HashSet::default();
    for candidate in &candidates {
        semantic_keys.insert(definition_symbol_key(candidate));
    }
    let status = if semantic_keys.len() == 1 {
        DefinitionLookupStatus::Resolved
    } else {
        DefinitionLookupStatus::Ambiguous
    };
    let diagnostics = if semantic_keys.len() > 1 {
        vec![DefinitionLookupDiagnostic {
            kind: "ambiguous_definition".to_string(),
            message: "reference resolved to multiple workspace definitions".to_string(),
        }]
    } else {
        Vec::new()
    };
    DefinitionLookupOutcome {
        status,
        reference: None,
        definitions: if status == DefinitionLookupStatus::Resolved {
            candidates
        } else {
            Vec::new()
        },
        diagnostics,
    }
}

fn definition_symbol_key(unit: &CodeUnit) -> (String, String) {
    (unit.fq_name(), format!("{:?}", unit.kind()))
}

fn boundary(message: String) -> DefinitionLookupOutcome {
    diagnostic_outcome(
        DefinitionLookupStatus::UnresolvableImportBoundary,
        "unresolvable_import_boundary",
        message,
    )
}

fn no_definition(kind: impl Into<String>, message: impl Into<String>) -> DefinitionLookupOutcome {
    diagnostic_outcome(DefinitionLookupStatus::NoDefinition, kind, message)
}

fn diagnostic_outcome(
    status: DefinitionLookupStatus,
    kind: impl Into<String>,
    message: impl Into<String>,
) -> DefinitionLookupOutcome {
    DefinitionLookupOutcome {
        status,
        reference: None,
        definitions: Vec::new(),
        diagnostics: vec![DefinitionLookupDiagnostic {
            kind: kind.into(),
            message: message.into(),
        }],
    }
}

fn sort_units(units: &mut [CodeUnit]) {
    units.sort_by(|left, right| {
        rel_path_string(left.source())
            .cmp(&rel_path_string(right.source()))
            .then_with(|| left.fq_name().cmp(&right.fq_name()))
            .then_with(|| left.signature().cmp(&right.signature()))
    });
}
