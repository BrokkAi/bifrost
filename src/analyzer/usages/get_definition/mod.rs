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
use crate::analyzer::usages::model::{ExportEntry, ImportBinder, ImportKind};
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
    resolve_analyzer, resolve_include_targets,
};
use crate::hash::{HashMap, HashSet};
use crate::path_utils::rel_path_string;
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tree_sitter::{Node, Parser, Tree};

mod cpp;
mod csharp;
mod go;
mod java;
mod js_ts;
mod php;
mod python;
mod rust;
mod scala;

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
        js_ts::jsts_site_for_focus(site)
    } else {
        site
    };

    let tree = context.tree(&request.file, language, &source);
    let resolved = match language {
        Language::Rust => rust::resolve_rust(
            analyzer,
            context.support,
            &request.file,
            &source,
            tree.as_ref(),
            &site,
        ),
        Language::JavaScript | Language::TypeScript => js_ts::resolve_js_ts(
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
            go::resolve_go(
                analyzer,
                context.support,
                &request.file,
                &source,
                &site,
                go_graph.as_deref(),
            )
        }
        Language::Java => java::resolve_java(
            analyzer,
            context.support,
            &request.file,
            &source,
            tree.as_ref(),
            &site,
        ),
        Language::Php => php::resolve_php(
            analyzer,
            context.support,
            &request.file,
            &source,
            tree.as_ref(),
            &site,
        ),
        Language::Python => python::resolve_python(
            analyzer,
            context.support,
            &request.file,
            &source,
            tree.as_ref(),
            &site,
        ),
        Language::CSharp => csharp::resolve_csharp(
            analyzer,
            context.support,
            &request.file,
            &source,
            tree.as_ref(),
            &site,
        ),
        Language::Cpp => cpp::resolve_cpp(
            analyzer,
            context,
            &request.file,
            &source,
            tree.as_ref(),
            &site,
        ),
        Language::Scala => scala::resolve_scala(
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

pub(crate) fn byte_offset_for_character_column(
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
        if left >= 2 && &bytes[left - 2..left] == b"::" {
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
        if right + 2 <= bytes.len() && &bytes[right..right + 2] == b"::" {
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

fn dotted_reference_segments(site: &ResolvedReferenceSite) -> Option<Vec<(String, usize, usize)>> {
    let mut segments = Vec::new();
    let mut offset = 0usize;
    for part in site.text.split('.') {
        if part.is_empty()
            || !part
                .chars()
                .all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        {
            return None;
        }
        let start = offset;
        let end = start + part.len();
        segments.push((part.to_string(), start, end));
        offset = end + 1;
    }
    Some(segments)
}

fn dotted_focus_segment_index(
    site: &ResolvedReferenceSite,
    segments: &[(String, usize, usize)],
) -> Option<usize> {
    let focus = site.focus_start_byte.checked_sub(site.range.start_byte)?;
    segments
        .iter()
        .position(|(_, start, end)| *start <= focus && focus < *end)
}

fn parse_tree_for_language(file: &ProjectFile, language: Language, source: &str) -> Option<Tree> {
    match language {
        Language::JavaScript | Language::TypeScript => {
            js_ts::parse_js_ts_tree(file, source, language)
        }
        Language::Cpp => cpp::parse_cpp_tree(source),
        Language::Scala => scala::parse_scala_tree(source),
        Language::Java => java::parse_java_tree(source),
        Language::Php => php::parse_php_tree(source),
        Language::CSharp => csharp::parse_csharp_tree(source),
        Language::Python => python::parse_python_tree(source),
        Language::Rust => rust::parse_rust_tree(source),
        Language::Go | Language::None => None,
    }
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

#[cfg(test)]
mod tests {
    use super::expand_reference_expression;

    #[test]
    fn expand_reference_expression_keeps_ascii_separator_checks_byte_pure() {
        let source = "回.helper";
        let start = source.find("helper").expect("target");
        let end = start + "helper".len();

        assert_eq!(
            expand_reference_expression(source, start, end),
            (start - 1, end)
        );

        let source = "helper:回";
        let start = source.find("helper").expect("target");
        let end = start + "helper".len();

        assert_eq!(
            expand_reference_expression(source, start, end),
            (start, end)
        );
    }
}
