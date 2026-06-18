use crate::analyzer::common::language_for_file;
use crate::analyzer::usages::cpp_graph::{
    CppTargetKind, CppVisibilityIndex, cpp_first_type_child, cpp_is_declaration_name,
    cpp_is_declarator_node, cpp_name_for, extract_variable_name, normalize_cpp_type_text,
};
use crate::analyzer::usages::csharp_graph::{
    csharp_first_type_child, csharp_is_declaration_name, csharp_is_type_reference_node,
    csharp_node_text, csharp_reference_type_text, member_access_name as csharp_member_access_name,
    member_access_receiver as csharp_member_access_receiver, seed_csharp_bindings_before,
};
use crate::analyzer::usages::go_graph::{
    GoProjectGraph, build_workspace_go_graph, default_go_import_local_name, extract_go_import_path,
    preparse_go_files, resolve_go_reference,
};
use crate::analyzer::usages::inverted_edges::{ClassRangeIndex, first_precise};
use crate::analyzer::usages::js_ts_graph::compute_jsts_import_binder;
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::usages::model::ImportKind;
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
    ScalaNameResolver, ScalaProjectTypes, scala_import_path, scala_node_text,
};
use crate::analyzer::{
    AliasResolver, CSharpAnalyzer, CodeUnit, CppAnalyzer, DefinitionLookupIndex, GoAnalyzer,
    IAnalyzer, ImportAnalysisProvider, JavaAnalyzer, Language, PhpAnalyzer, ProjectFile,
    PythonAnalyzer, Range, RustAnalyzer, ScalaAnalyzer, cpp_node_text,
    parse_php_use_aliases_from_source, quoted_include_paths, resolve_analyzer,
    resolve_include_targets,
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
    pub(crate) definition: Option<CodeUnit>,
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
            .or_insert_with(|| parse_tree_for_language(language, source))
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
            &site.text,
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
            let imported = rust_import_candidates(rust, support, file, source, reference);
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
    rust: &crate::analyzer::RustAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    reference: &str,
) -> Vec<CodeUnit> {
    let statement_candidates =
        rust_import_statement_candidates(rust, support, file, source, reference);
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
    rust: &crate::analyzer::RustAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    reference: &str,
) -> Vec<CodeUnit> {
    for raw in source.lines() {
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

fn rust_module_files_from_path(file: &ProjectFile, module_specifier: &str) -> Vec<ProjectFile> {
    let Some(relative_module) = rust_relative_module_path(file, module_specifier) else {
        return Vec::new();
    };
    let mut files = Vec::new();
    for rel_path in [
        relative_module.with_extension("rs"),
        relative_module.join("mod.rs"),
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
        })?;
    Some(module.to_string_lossy().replace("::", "/").into())
}

fn rust_reference_looks_external(reference: &str) -> bool {
    reference
        .split("::")
        .next()
        .is_some_and(|root| !matches!(root, "crate" | "self" | "super") && root != reference)
}

fn parse_tree_for_language(language: Language, source: &str) -> Option<Tree> {
    match language {
        Language::JavaScript | Language::TypeScript => parse_js_ts_tree(source, language),
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
    reference: &str,
) -> DefinitionLookupOutcome {
    let Some(tree) = tree else {
        return no_definition("jsts_parse_failed", "JS/TS source could not be parsed");
    };
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
            );
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
            );
        }
    }

    let same_file = support.file_identifier(file, reference);
    if !same_file.is_empty() {
        return candidates_outcome(same_file);
    }

    no_definition(
        "no_indexed_definition",
        format!("`{reference}` did not resolve to an indexed JS/TS definition"),
    )
}

fn resolve_js_ts_module_binding(
    file: &ProjectFile,
    language: Language,
    module: &str,
    exported_name: &str,
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    aliases: Option<&AliasResolver>,
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

    let mut candidates = support.file_identifier_in_files(&files, exported_name);
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
    }
    if candidates.is_empty() {
        return no_definition(
            "no_indexed_definition",
            format!("`{exported_name}` is not indexed in `{module}`"),
        );
    }
    candidates_outcome(candidates)
}

fn is_bare_js_ts_specifier(module: &str) -> bool {
    !module.starts_with("./") && !module.starts_with("../") && !module.starts_with('/')
}

fn parse_js_ts_tree(source: &str, language: Language) -> Option<Tree> {
    let mut parser = Parser::new();
    let tree_sitter_language = match language {
        Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
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
                resolve_go_shadowed_selector_chain(analyzer, support, file, source, site, reference)
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
            return no_definition(
                "no_indexed_definition",
                format!("`{name}` is not indexed in Go package `{package}`"),
            );
        }
    }

    let package = go_package_name(file, source);
    if let Some((qualifier, name)) = reference.split_once('.') {
        let imports = go_import_paths(go, file);
        if let Some(import_path) = imports.get(qualifier) {
            let candidates = support.fqn(&format!("{import_path}.{name}"));
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
        let candidates = support.fqn_candidates([format!("{package}.{qualifier}.{name}")]);
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
        return no_definition(
            "no_indexed_definition",
            format!("`{reference}` did not resolve to an indexed Go definition"),
        );
    }

    let candidates = support.fqn(&format!("{package}.{reference}"));
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }
    let same_file = support.file_identifier(file, reference);
    if !same_file.is_empty() {
        return candidates_outcome(same_file);
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

fn resolve_go_shadowed_selector_chain(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
    site: &ResolvedReferenceSite,
    reference: &str,
) -> Option<DefinitionLookupOutcome> {
    let segments: Vec<_> = reference.split('.').collect();
    if segments.len() < 3 {
        return None;
    }

    let mut parser = Parser::new();
    parser.set_language(&tree_sitter_go::LANGUAGE.into()).ok()?;
    let tree = parser.parse(source, None)?;
    let mut owner_fqn = go_receiver_binding_type_fqn(
        support,
        file,
        source,
        tree.root_node(),
        segments[0],
        site.focus_start_byte,
    )?;
    for field in &segments[1..segments.len() - 1] {
        owner_fqn = go_indexed_field_type_fqn(analyzer, support, &owner_fqn, field)?;
    }
    let member = segments.last()?;
    let candidates = support.fqn(&format!("{owner_fqn}.{member}"));
    (!candidates.is_empty()).then(|| candidates_outcome(candidates))
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

fn go_parameter_type_for_name<'tree>(
    parameter_list: Node<'tree>,
    source: &str,
    name: &str,
) -> Option<Node<'tree>> {
    let mut cursor = parameter_list.walk();
    for parameter in parameter_list.named_children(&mut cursor) {
        if parameter.kind() != "parameter_declaration" {
            continue;
        }
        let mut names = Vec::new();
        let mut type_node = None;
        let mut inner = parameter.walk();
        for child in parameter.named_children(&mut inner) {
            match child.kind() {
                "identifier" => names.push(go_node_text(child, source)),
                _ => type_node = Some(child),
            }
        }
        if names.iter().any(|candidate| *candidate == name) {
            return type_node;
        }
    }
    None
}

fn go_indexed_field_type_fqn(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    owner_fqn: &str,
    field: &str,
) -> Option<String> {
    let field_unit = support
        .fqn(&format!("{owner_fqn}.{field}"))
        .into_iter()
        .next()?;
    let signature = field_unit
        .signature()
        .map(str::to_string)
        .or_else(|| analyzer.signatures(&field_unit).into_iter().next().cloned())?;
    let type_text = signature
        .trim()
        .strip_prefix(field)
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    let package = owner_fqn.rsplit_once('.').map(|(package, _)| package)?;
    go_resolve_type_name_in_package(support, package, type_text)
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
    let trimmed = type_text
        .trim()
        .trim_start_matches('*')
        .trim_start_matches("[]")
        .trim();
    let name = trimmed
        .split(['[', '{', ' ', '\t', '\n', '\r'])
        .next()
        .unwrap_or(trimmed)
        .rsplit_once('.')
        .map(|(_, name)| name)
        .unwrap_or(trimmed)
        .trim();
    (!name.is_empty()).then_some(name)
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
                visibility.as_ref(),
                source,
                type_node,
            )
        }
        Some(CppReferenceNode::Call(call)) => resolve_cpp_call(
            analyzer,
            support,
            file,
            visibility.as_ref(),
            source,
            root,
            call,
        ),
        Some(CppReferenceNode::Field(field)) => resolve_cpp_field(
            analyzer,
            support,
            file,
            visibility.as_ref(),
            source,
            root,
            field,
        ),
        Some(CppReferenceNode::Identifier(identifier)) => {
            if cpp_is_declaration_name(node) {
                return no_definition(
                    "declaration_or_import_site",
                    format!("`{}` is not a C++ reference site", site.text),
                );
            }
            let text = cpp_node_text(identifier, source);
            if text.is_empty() {
                return no_definition("no_reference_text", "C++ identifier is blank");
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

fn resolve_cpp_call(
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    visibility: &CppVisibilityIndex,
    source: &str,
    root: Node<'_>,
    call: Node<'_>,
) -> DefinitionLookupOutcome {
    let Some(function) = call.child_by_field_name("function") else {
        return no_definition("no_function_name", "C++ call expression has no function");
    };
    match function.kind() {
        "field_expression" => {
            resolve_cpp_field(analyzer, support, file, visibility, source, root, function)
        }
        "qualified_identifier" => {
            let text = cpp_node_text(function, source);
            let mut candidates = cpp_visible_name_candidates(
                visibility,
                file,
                support,
                text,
                Some(CppTargetKind::FreeFunction),
                cpp_lexical_namespace(function, source).as_deref(),
            );
            if !candidates.is_empty() {
                return candidates_outcome(candidates);
            }
            if let Some(scope) = function.child_by_field_name("scope")
                && let Some(name) = function.child_by_field_name("name")
            {
                let member = cpp_node_text(name, source);
                if let Some(owner) = visibility.resolve_type(file, cpp_node_text(scope, source)) {
                    candidates = cpp_member_candidates(support, vec![owner], member);
                    if !candidates.is_empty() {
                        return candidates_outcome(candidates);
                    }
                }
            }
            if cpp_unresolved_include_boundary(analyzer, file, text) {
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
            let name = cpp_node_text(function, source);
            if name.is_empty() {
                return no_definition("no_function_name", "C++ call name is blank");
            }
            let bindings =
                cpp_bindings_before(visibility, file, source, root, function.start_byte());
            if bindings.is_shadowed(name) {
                return no_definition(
                    "local_variable_reference",
                    format!("`{name}` is a local C++ value"),
                );
            }
            let candidates = cpp_visible_name_candidates(
                visibility,
                file,
                support,
                name,
                Some(CppTargetKind::FreeFunction),
                None,
            );
            if !candidates.is_empty() {
                return candidates_outcome(candidates);
            }
            if let Some(owner) = cpp_enclosing_class(analyzer, file, function.start_byte()) {
                let member_candidates = cpp_member_candidates(support, vec![owner], name);
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
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    visibility: &CppVisibilityIndex,
    source: &str,
    root: Node<'_>,
    field: Node<'_>,
) -> DefinitionLookupOutcome {
    let Some(name_node) = field.child_by_field_name("field") else {
        return no_definition("no_member_name", "C++ field expression has no member name");
    };
    let member = cpp_node_text(name_node, source);
    let Some(receiver) = field
        .child_by_field_name("argument")
        .or_else(|| field.named_child(0))
    else {
        return no_definition("no_member_receiver", "C++ field expression has no receiver");
    };
    let owners = cpp_receiver_type_units(analyzer, visibility, file, source, root, receiver);
    let candidates = cpp_member_candidates(support, owners, member);
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
            && !cpp_unit_matches_kind(unit, kind)
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

fn cpp_unit_matches_kind(unit: &CodeUnit, kind: CppTargetKind) -> bool {
    match kind {
        CppTargetKind::FreeFunction => unit.is_function(),
        CppTargetKind::Type => unit.is_class() || cpp_unit_is_type_alias(unit),
        CppTargetKind::Constructor
        | CppTargetKind::Method
        | CppTargetKind::GlobalField
        | CppTargetKind::MemberField => true,
    }
}

fn cpp_unit_is_type_alias(unit: &CodeUnit) -> bool {
    unit.is_field()
        && unit.signature().is_some_and(|signature| {
            signature.starts_with("typedef ") || signature.starts_with("using ")
        })
}

fn cpp_member_candidates(
    support: &DefinitionLookupIndex,
    owners: Vec<CodeUnit>,
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

fn cpp_receiver_type_units(
    analyzer: &dyn IAnalyzer,
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    receiver: Node<'_>,
) -> Vec<CodeUnit> {
    match receiver.kind() {
        "identifier" => {
            let name = cpp_node_text(receiver, source);
            let bindings =
                cpp_bindings_before(visibility, file, source, root, receiver.start_byte());
            if let Some(unit) = first_precise(&bindings, name) {
                return vec![unit];
            }
            if bindings.is_shadowed(name) {
                Vec::new()
            } else {
                visibility.resolve_type(file, name).into_iter().collect()
            }
        }
        "this" => cpp_enclosing_class(analyzer, file, receiver.start_byte())
            .into_iter()
            .collect(),
        "parenthesized_expression" | "pointer_expression" => receiver
            .child_by_field_name("argument")
            .or_else(|| receiver.named_child(0))
            .map(|inner| cpp_receiver_type_units(analyzer, visibility, file, source, root, inner))
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn cpp_enclosing_class(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    byte: usize,
) -> Option<CodeUnit> {
    let fqn = ClassRangeIndex::build(analyzer, file)
        .enclosing(byte)?
        .to_string();
    analyzer.definitions(&fqn).next().cloned()
}

const CPP_SCOPE_NODES: &[&str] = &[
    "compound_statement",
    "function_definition",
    "lambda_expression",
    "for_statement",
    "while_statement",
    "if_statement",
];

fn cpp_bindings_before(
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    cutoff_start: usize,
) -> LocalInferenceEngine<CodeUnit> {
    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    cpp_seed_active_path(visibility, file, source, root, cutoff_start, &mut bindings);
    bindings
}

fn cpp_seed_active_path(
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    cutoff_start: usize,
    bindings: &mut LocalInferenceEngine<CodeUnit>,
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
            cpp_seed_typed_binding(visibility, file, source, node, bindings)
        }
        "declaration" | "field_declaration" if node.start_byte() < cutoff_start => {
            cpp_seed_variable_declaration(visibility, file, source, node, cutoff_start, bindings)
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.start_byte() >= cutoff_start {
            break;
        }
        cpp_seed_active_path(visibility, file, source, child, cutoff_start, bindings);
    }
}

fn cpp_seed_typed_binding(
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    bindings: &mut LocalInferenceEngine<CodeUnit>,
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
        visibility,
        file,
        source,
        &name,
        type_text.as_deref(),
        None,
        bindings,
    );
}

fn cpp_seed_variable_declaration(
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    cutoff_start: usize,
    bindings: &mut LocalInferenceEngine<CodeUnit>,
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
        if declarator.kind() == "function_declarator" {
            continue;
        }
        if let Some(name) = extract_variable_name(declarator, source) {
            let value = child
                .child_by_field_name("value")
                .filter(|value| value.end_byte() <= cutoff_start);
            cpp_seed_binding(
                visibility,
                file,
                source,
                &name,
                type_text.as_deref(),
                value,
                bindings,
            );
        }
    }
}

fn cpp_seed_binding(
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    name: &str,
    type_text: Option<&str>,
    value: Option<Node<'_>>,
    bindings: &mut LocalInferenceEngine<CodeUnit>,
) {
    if name.is_empty() {
        return;
    }
    let resolved = type_text
        .filter(|text| *text != "auto")
        .and_then(|text| visibility.resolve_type(file, text))
        .or_else(|| {
            value.and_then(|value| cpp_infer_type_from_value(visibility, file, source, value))
        });
    match resolved {
        Some(unit) => bindings.seed_symbol(name.to_string(), unit),
        None => bindings.declare_shadow(name.to_string()),
    }
}

fn cpp_infer_type_from_value(
    visibility: &CppVisibilityIndex,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
) -> Option<CodeUnit> {
    match node.kind() {
        "new_expression" => {
            let text = cpp_node_text(node, source).trim();
            let rest = text.strip_prefix("new ").unwrap_or(text);
            visibility.resolve_type(file, rest.split(['(', '{']).next().unwrap_or(rest))
        }
        "call_expression" => node
            .child_by_field_name("function")
            .and_then(|function| visibility.resolve_type(file, cpp_node_text(function, source))),
        _ => None,
    }
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
        if import.contains('<') && import.contains('>') {
            return true;
        }
        quoted_include_paths(std::slice::from_ref(import))
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
        Some(ScalaReferenceNode::Field(field)) => {
            resolve_scala_field(analyzer, support, file, source, &resolver, root, field)
        }
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
        "field_expression" => resolve_scala_field(
            ctx.analyzer,
            ctx.support,
            ctx.file,
            ctx.source,
            resolver,
            root,
            function,
        ),
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
                let candidates = ctx.support.fqn(&format!("{}.{}", owner.fq_name(), name));
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
    analyzer: &dyn IAnalyzer,
    support: &DefinitionLookupIndex,
    file: &ProjectFile,
    source: &str,
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
    let member = scala_node_text(field_node, source).trim();
    let Some(receiver) = field.child_by_field_name("value") else {
        return no_definition(
            "no_member_receiver",
            "Scala field expression has no receiver",
        );
    };
    if let Some(owner) = scala_receiver_type_fqn(
        analyzer,
        file,
        source,
        resolver,
        root,
        receiver,
        field.start_byte(),
    ) {
        let candidates = support.fqn(&format!("{owner}.{member}"));
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
    }
    no_definition(
        "unsupported_scala_receiver",
        format!("receiver for Scala member `{member}` is not resolved"),
    )
}

fn scala_receiver_type_fqn(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    receiver: Node<'_>,
    cutoff_start: usize,
) -> Option<String> {
    match receiver.kind() {
        "identifier" | "type_identifier" => {
            let name = scala_node_text(receiver, source).trim();
            if name == "this" {
                return ClassRangeIndex::build(analyzer, file)
                    .enclosing(receiver.start_byte())
                    .map(str::to_string);
            }
            let bindings = scala_bindings_before(resolver, source, root, cutoff_start);
            first_precise(&bindings, name).or_else(|| {
                scala_enclosing_class_parameter_type(
                    analyzer, file, receiver, name, resolver, source,
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
                if parameter.kind() != "class_parameter" {
                    continue;
                }
                let Some(param_name) = parameter.child_by_field_name("name") else {
                    continue;
                };
                if scala_node_text(param_name, source).trim() != name {
                    continue;
                }
                return parameter.child_by_field_name("type").and_then(|type_node| {
                    let type_text = scala_node_text(type_node, source);
                    resolver.resolve(type_text).or_else(|| {
                        scala_same_package_type_fqn(current_class.as_deref()?, type_text)
                    })
                });
            }
            return None;
        }
        current = parent.parent();
    }
    None
}

fn scala_same_package_type_fqn(current_class_fqn: &str, type_text: &str) -> Option<String> {
    let simple = scala_simple_name(type_text);
    if simple.is_empty() || simple.contains('.') {
        return None;
    }
    current_class_fqn
        .rsplit_once('.')
        .map(|(package, _)| format!("{package}.{simple}"))
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
            resolver.resolve(type_text)
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
        .and_then(|type_node| resolver.resolve(scala_node_text(type_node, source)))
        .or_else(|| {
            node.child_by_field_name("value")
                .filter(|value| value.end_byte() <= cutoff_start)
                .and_then(|value| scala_constructed_type(value, resolver, source))
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
    if node.kind() != "instance_expression" {
        return None;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == "type_identifier" || child.kind() == "generic_type")
        .and_then(|type_node| resolver.resolve(scala_node_text(type_node, source)))
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
    let Some(node) = smallest_named_node_covering(root, site.range.start_byte, site.range.end_byte)
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
            resolve_java_type_reference(java, support, file, source, node)
        }
        "object_creation_expression" => node
            .child_by_field_name("type")
            .map(|type_node| resolve_java_type_reference(java, support, file, source, type_node))
            .unwrap_or_else(|| {
                no_definition(
                    "no_indexed_definition",
                    format!("`{}` did not resolve to an indexed Java type", site.text),
                )
            }),
        "method_invocation" => {
            resolve_java_method_invocation(analyzer, support, file, source, root, node)
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
            return java_member_candidates(support, &owner.fq_name(), name);
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
        return java_member_candidates(support, owner_fqn, name);
    }

    no_definition(
        "no_indexed_definition",
        format!("`{name}` did not resolve to an indexed Java method"),
    )
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
        return java_member_candidates(support, &owner.fq_name(), field);
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
    java_receiver_type_for_java(java, file, source, root, object).or_else(|| {
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
    java: &JavaAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    object: Node<'_>,
) -> Option<CodeUnit> {
    match object.kind() {
        "type_identifier" | "scoped_type_identifier" | "generic_type" => {
            let raw = java_node_text(object, source);
            java.resolve_type_name_in_file(file, normalize_java_type_text(raw))
        }
        "identifier" => {
            let name = java_node_text(object, source);
            java_type_of_identifier_before(java, file, source, root, name, object.start_byte())
        }
        _ => None,
    }
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
    support: &DefinitionLookupIndex,
    owner_fqn: &str,
    member: &str,
) -> DefinitionLookupOutcome {
    let candidates = support.fqn(&format!("{owner_fqn}.{member}"));
    if candidates.is_empty() {
        no_definition(
            "no_indexed_definition",
            format!("`{owner_fqn}.{member}` is not indexed as a Java definition"),
        )
    } else {
        candidates_outcome(candidates)
    }
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
            php_member_outcome(support, owner, member)
        }
        Some(PhpReferenceNode::InstanceMember { object, name }) => {
            let member = php_node_text(name, source).trim_start_matches('$');
            let bindings =
                php_bindings_before(php, file, source, root, site.range.start_byte, &ctx);
            let owner = php_instance_receiver_fqn(object, source, &class_ranges, &bindings);
            php_member_outcome(support, owner, member)
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
            let member = csharp_node_text(name, source);
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
            csharp_member_outcome(analyzer, support, owners, member)
        }
        Some(CSharpReferenceNode::UnqualifiedMember(name)) => {
            let member = csharp_node_text(name, source);
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
            let outcome = csharp_member_outcome(analyzer, support, owners, member);
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
        if parent.kind() == "member_access_expression"
            && (csharp_member_access_name(parent) == Some(current)
                || csharp_member_access_name(parent) == Some(original))
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
) -> DefinitionLookupOutcome {
    if owners.is_empty() {
        return no_definition(
            "unsupported_csharp_receiver",
            format!("receiver for C# member `{member}` is not resolved"),
        );
    };

    let mut candidates = Vec::new();
    for owner in &owners {
        candidates.extend(support.fqn(&format!("{}.{}", owner.fq_name(), member)));
        if let Some(provider) = analyzer.type_hierarchy_provider() {
            for ancestor in provider.get_ancestors(owner) {
                candidates.extend(support.fqn(&format!("{}.{}", ancestor.fq_name(), member)));
            }
        }
    }
    sort_units(&mut candidates);
    candidates.dedup();
    if candidates.is_empty() {
        no_definition(
            "no_indexed_definition",
            format!("C# member `{member}` is not indexed as a definition"),
        )
    } else {
        candidates_outcome(candidates)
    }
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
                csharp_visible_type_candidates(csharp, file, name)
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

fn php_reference_node(node: Node<'_>) -> Option<PhpReferenceNode<'_>> {
    let node = php_qualified_reference_node(node);
    match node.kind() {
        "object_creation_expression" => php_object_creation_type(node).map(PhpReferenceNode::Type),
        "named_type" => (!php_is_in_object_creation(node)).then_some(PhpReferenceNode::Type(node)),
        "function_call_expression" => node
            .child_by_field_name("function")
            .filter(|name| matches!(name.kind(), "name" | "qualified_name"))
            .map(PhpReferenceNode::Function),
        "scoped_call_expression" | "class_constant_access_expression" => {
            let scope = node.child_by_field_name("scope")?;
            let name = node.child_by_field_name("name")?;
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
                    if parent.child_by_field_name("name") == Some(node) =>
                {
                    let scope = parent.child_by_field_name("scope")?;
                    Some(PhpReferenceNode::StaticMember { scope, name: node })
                }
                "member_call_expression" | "member_access_expression"
                    if parent.child_by_field_name("name") == Some(node) =>
                {
                    let object = parent.child_by_field_name("object")?;
                    Some(PhpReferenceNode::InstanceMember { object, name: node })
                }
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
        semantic_keys.insert(definition_semantic_key(candidate));
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
        definition: candidates
            .into_iter()
            .next()
            .filter(|_| status == DefinitionLookupStatus::Resolved),
        diagnostics,
    }
}

fn definition_semantic_key(unit: &CodeUnit) -> (String, Option<String>, String) {
    (
        unit.fq_name(),
        unit.signature().map(str::to_string),
        format!("{:?}", unit.kind()),
    )
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
        definition: None,
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
