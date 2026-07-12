use crate::analyzer::common::language_for_file;
use crate::analyzer::lexical_definitions::{
    LexicalBindingResolution, LexicalDefinition, resolve_lexical_binding,
};
use crate::analyzer::usages::cpp_graph::{
    CppTargetKind, CppVisibilityIndex, cpp_call_arity, cpp_constructor_type_node,
    cpp_first_type_child, cpp_function_return_type_text, cpp_is_declaration_name,
    cpp_is_declarator_node, cpp_name_for, cpp_reference_fqn_candidates, cpp_signature_arity,
    cpp_split_top_level_commas, extract_variable_name, normalize_cpp_type_text,
};
use crate::analyzer::usages::csharp_graph::{
    csharp_argument_count, csharp_first_type_child, csharp_is_declaration_name,
    csharp_is_extension_method, csharp_is_type_reference_node, csharp_member_declared_type_fq_name,
    csharp_method_return_type_fq_name, csharp_node_text, csharp_object_created_type,
    csharp_object_initializer_for_label, csharp_reference_type_text, csharp_signature_arity,
    member_access_name as csharp_member_access_name,
    member_access_receiver as csharp_member_access_receiver, seed_csharp_bindings_before,
};
use crate::analyzer::usages::go_graph::{
    GoIndexedMemberLookup, GoReferenceResolution, default_go_import_local_name,
    extract_go_import_path, go_embedded_field_unit_type_text, go_simple_type_name,
    go_type_name_parts, go_unique_indexed_member_candidate_at_nearest_depth,
    resolve_go_reference_with_namespaces,
};
use crate::analyzer::usages::inverted_edges::{ClassRangeIndex, first_precise};
use crate::analyzer::usages::java_graph::java_signature_arity;
use crate::analyzer::usages::js_ts_graph::{
    JsTsReceiverFactProvider, cached_jsts_index, compute_jsts_import_binder,
};
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::usages::model::{ImportBinder, ImportKind};
use crate::analyzer::usages::php_graph::{
    FileContext, php_node_text, php_qualified_candidate_text, resolve_php_constant,
    resolve_php_function, resolve_php_type,
};
use crate::analyzer::usages::python_graph::{
    collect_assigned_identifiers, collect_scope_facts_from_parsed_source, enclosing_scope_facts,
    is_declaration_identifier as python_is_declaration_identifier, python_slice,
    resolve_receiver_type as resolve_python_receiver_type,
};
use crate::analyzer::usages::receiver_analysis::{ReceiverAnalysisBudget, ReceiverAnalysisOutcome};
pub(crate) use crate::analyzer::usages::reference_site::byte_offset_for_character_column;
pub(crate) use crate::analyzer::usages::reference_site::{
    ResolvedReferenceSite, SourceLocationRequest, resolve_reference_site_with_line_starts,
    smallest_named_node_covering,
};
use crate::analyzer::usages::ruby_graph::{
    ReceiverMode as RubyReceiverMode, ReceiverType as RubyReceiverType, RubySemanticIndex,
    is_call_method_identifier as ruby_is_call_method_identifier,
    is_declaration_constant as ruby_is_declaration_constant,
    is_declaration_identifier as ruby_is_declaration_identifier,
    is_dynamic_dispatch_method as ruby_is_dynamic_dispatch_method,
    is_plain_assignment_left_variable as ruby_is_plain_assignment_left_variable,
    method_receiver_mode as ruby_method_receiver_mode, node_text as ruby_node_text,
    ruby_enclosing_receiver, ruby_field_reference_owner_and_scope,
    ruby_field_target as ruby_field_target_from_code_unit, ruby_receiver_type,
    ruby_seed_assignment, ruby_seed_parameter_shadows, ruby_type_owner,
    symbol_or_string_value as ruby_symbol_or_string_value,
};
use crate::analyzer::usages::scala_graph::{
    ScalaNameResolver, ScalaProjectTypes, import_candidate_fq_names,
    import_candidate_owner_fq_names, package_name_of as scala_package_name_of,
    scala_builtin_type_name, scala_extension_receiver_matches_resolved, scala_import_path,
    scala_literal_type_name, scala_node_text, scala_normalized_fq_name,
    scala_visible_type_fqn_from_index,
};
use crate::analyzer::{
    AliasResolver, CSharpAnalyzer, CodeUnit, CppAnalyzer, DefinitionLookupIndex, GoAnalyzer,
    IAnalyzer, ImportAnalysisProvider, JavaAnalyzer, Language, PhpAnalyzer, ProjectFile,
    PythonAnalyzer, Range, RubyAnalyzer, RustAnalyzer, ScalaAnalyzer, cpp_include_paths,
    cpp_node_text, resolve_analyzer, resolve_include_targets,
};
use crate::hash::{HashMap, HashSet};
use crate::path_utils::rel_path_string;
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
pub(crate) use rust::{
    RustTypeLookupCache, rust_expression_type_definition_fqn_cached, rust_is_type_definition,
    rust_resolve_type_node_fqn,
};
use std::sync::{Arc, OnceLock};
use tree_sitter::{Node, Parser, Tree};

mod call_sites;
mod cpp;
mod csharp;
mod go;
mod java;
pub(crate) mod js_ts;
mod php;
mod python;
mod ruby;
mod rust;
mod scala;

pub(crate) use call_sites::{
    call_reference_ranges, call_signature_context, is_call_reference_range_in_tree,
};
pub(crate) use csharp::{CSharpTypeLookupResolution, csharp_type_lookup_resolution};
pub(crate) use go::{GoTypeLookupResolutionKind, go_type_lookup_resolution};
pub(crate) use java::{
    JavaTypeLookupResolution, java_lombok_accessor_field_candidates, java_type_lookup_resolution,
};
pub(crate) use scala::{ScalaTypeLookupResolution, scala_type_lookup_resolution};

/// Resolve a bare `name` against the lexically enclosing scope chain, innermost
/// first — the language-agnostic generalization of Java's nested-type resolution
/// (`java_nested_type_from_context`).
///
/// Finds the enclosing declaration at `byte` via the generic `enclosing_code_unit`
/// primitive (which every analyzer implements), then walks its fully-qualified name
/// outward one segment at a time, trying `{scope}.{name}` at each level and
/// returning the innermost match. This makes a bare reference inside `mod b` (Rust)
/// / `namespace B` (C++/C#) / `class B` resolve to `B`'s member rather than a
/// same-named sibling scope's — the #431 scope-blind collapse — because it uses the
/// reference's *position* instead of a flat, position-blind short-name map.
///
/// Walking fqn segments (rather than `parent_of`) is what makes it uniform across
/// languages: scopes that are CodeUnits (Rust modules) and scopes that are only fqn
/// prefixes (C#/C++ namespaces, which are not indexed as units) are handled the same
/// way. `accept` filters the wanted declaration kind (e.g. `CodeUnit::is_class`).
pub(super) fn resolve_in_enclosing_scopes(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    name: &str,
    byte: usize,
    accept: impl Fn(&CodeUnit) -> bool,
) -> Option<CodeUnit> {
    if name.is_empty() || name.contains('.') {
        return None;
    }
    let range = Range {
        start_byte: byte,
        end_byte: byte + 1,
        start_line: 0,
        end_line: 0,
    };
    let mut scope = analyzer.enclosing_code_unit(file, &range)?.fq_name();
    loop {
        if scope.is_empty() {
            // Only *enclosing* named scopes are tried here; the bare top level is
            // left to the caller's normal name resolution, which applies imports
            // and shadowing (so this cannot override a glob import / local shadow).
            return None;
        }
        let child_fqn = format!("{scope}.{name}");
        if let Some(child) = analyzer.definitions(&child_fqn).find(|unit| accept(unit)) {
            return Some(child);
        }
        match scope.rfind('.') {
            Some(idx) => scope.truncate(idx),
            None => return None,
        }
    }
}

pub(crate) const SCALA_UNSUPPORTED_CALL_TARGET_SHAPE: &str = "unsupported_scala_call_target_shape";
pub(crate) const SCALA_UNSUPPORTED_RECEIVER: &str = "unsupported_scala_receiver";

#[derive(Debug, Clone)]
pub(crate) struct DefinitionLookupRequest {
    pub(crate) file: ProjectFile,
    pub(crate) line: Option<usize>,
    pub(crate) column: Option<usize>,
    pub(crate) start_byte: Option<usize>,
    pub(crate) end_byte: Option<usize>,
}

impl DefinitionLookupRequest {
    fn as_source_location(&self) -> SourceLocationRequest {
        SourceLocationRequest {
            file: self.file.clone(),
            line: self.line,
            column: self.column,
            start_byte: self.start_byte,
            end_byte: self.end_byte,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DefinitionLookupOutcome {
    pub(crate) status: DefinitionLookupStatus,
    pub(crate) reference: Option<ResolvedReferenceSite>,
    pub(crate) definitions: Vec<CodeUnit>,
    pub(crate) lexical_definition: Option<LexicalDefinition>,
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

pub(crate) fn resolve_definition_batch_with_source(
    analyzer: &dyn IAnalyzer,
    requests: Vec<DefinitionLookupRequest>,
    file: ProjectFile,
    source: Arc<String>,
) -> Vec<DefinitionLookupOutcome> {
    let mut context = DefinitionBatchContext::new(analyzer);
    context.sources.insert(file, Ok(source));
    requests
        .into_iter()
        .map(|request| resolve_one(analyzer, &mut context, request))
        .collect()
}

pub(crate) fn resolve_call_reference_definition_with_source(
    analyzer: &dyn IAnalyzer,
    request: DefinitionLookupRequest,
    file: ProjectFile,
    source: Arc<String>,
) -> Option<DefinitionLookupOutcome> {
    let language = language_for_file(&request.file);
    if matches!(language, Language::None | Language::Ruby) {
        return None;
    }
    let start_byte = request.start_byte?;
    let end_byte = request.end_byte?;
    if start_byte >= end_byte {
        return None;
    }

    let mut context = DefinitionBatchContext::new(analyzer);
    context.sources.insert(file, Ok(source));
    let source = context.source(&request.file).ok()?;
    let tree = context.tree(&request.file, language, &source)?;
    if !is_call_reference_range_in_tree(&tree, language, start_byte, end_byte) {
        return None;
    }

    Some(resolve_one(analyzer, &mut context, request))
}

struct DefinitionBatchContext<'a> {
    analyzer: &'a dyn IAnalyzer,
    support: OnceLock<&'a DefinitionLookupIndex>,
    sources: HashMap<ProjectFile, Result<Arc<String>, String>>,
    trees: HashMap<(ProjectFile, Language), Option<Tree>>,
    line_starts: HashMap<ProjectFile, Arc<Vec<usize>>>,
    cpp_visibility: HashMap<ProjectFile, Arc<CppVisibilityIndex>>,
    scala_project_types: Option<Arc<ScalaProjectTypes>>,
}

impl<'a> DefinitionBatchContext<'a> {
    fn new(analyzer: &'a dyn IAnalyzer) -> Self {
        Self {
            analyzer,
            support: OnceLock::new(),
            sources: HashMap::default(),
            trees: HashMap::default(),
            line_starts: HashMap::default(),
            cpp_visibility: HashMap::default(),
            scala_project_types: None,
        }
    }

    fn support(&self) -> &'a DefinitionLookupIndex {
        self.support
            .get_or_init(|| self.analyzer.definition_lookup_index())
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

    fn line_starts(&mut self, file: &ProjectFile, source: &str) -> Arc<Vec<usize>> {
        self.line_starts
            .entry(file.clone())
            .or_insert_with(|| Arc::new(compute_line_starts(source)))
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
            .get_or_insert_with(|| scala.project_types())
            .clone()
    }
}

fn resolve_one(
    analyzer: &dyn IAnalyzer,
    context: &mut DefinitionBatchContext<'_>,
    request: DefinitionLookupRequest,
) -> DefinitionLookupOutcome {
    let language = language_for_file(&request.file);
    if matches!(language, Language::None) {
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

    let line_starts = context.line_starts(&request.file, &source);
    let site = match resolve_reference_site_with_line_starts(
        &request.as_source_location(),
        &source,
        &line_starts,
    ) {
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
    if let Some(tree) = tree.as_ref()
        && let Some(identifier) = source.get(site.focus_start_byte..site.focus_end_byte)
    {
        match resolve_lexical_binding(
            language,
            tree.root_node(),
            &source,
            site.focus_start_byte,
            site.focus_end_byte,
            identifier,
        ) {
            Some(LexicalBindingResolution::Parameter(definition)) => {
                return finish_lookup_outcome(lexical_definition_outcome(definition), site);
            }
            Some(LexicalBindingResolution::OtherLocal) => {
                return finish_lookup_outcome(
                    no_definition(
                        "local_binding",
                        format!("`{identifier}` resolves to a local non-parameter binding"),
                    ),
                    site,
                );
            }
            None => {}
        }
    }
    let resolved = match language {
        Language::Rust => rust::resolve_rust(
            analyzer,
            &rust::AnalyzerRustDefinitionProvider::new(analyzer),
            &request.file,
            &source,
            tree.as_ref(),
            &site,
        ),
        Language::JavaScript | Language::TypeScript => js_ts::resolve_js_ts(
            analyzer,
            context.support(),
            &request.file,
            language,
            &source,
            tree.as_ref(),
            &site,
        ),
        Language::Go => {
            let go = resolve_analyzer::<GoAnalyzer>(analyzer);
            let resolution = go.and_then(|go| {
                let tree = tree.as_ref()?;
                let file_package =
                    go.canonical_package_name_from_tree(&request.file, &source, tree.root_node());
                let (aliases, dot_imports) = go.definition_import_namespaces(&request.file);
                Some(resolve_go_reference_with_namespaces(
                    tree.root_node(),
                    &source,
                    &file_package,
                    aliases,
                    dot_imports,
                    &site,
                ))
            });
            if let Some(go_analyzer) = go {
                go::resolve_go(
                    analyzer,
                    &go::AnalyzerGoDefinitionProvider::new(go_analyzer),
                    &request.file,
                    &source,
                    &site,
                    resolution,
                )
            } else {
                no_definition("go_analyzer_unavailable", "Go analyzer is unavailable")
            }
        }
        Language::Java => java::resolve_java(
            analyzer,
            context.support(),
            &request.file,
            &source,
            tree.as_ref(),
            &site,
        ),
        Language::Php => php::resolve_php(
            analyzer,
            context.support(),
            &request.file,
            &source,
            tree.as_ref(),
            &site,
        ),
        Language::Python => python::resolve_python(
            analyzer,
            context.support(),
            &request.file,
            &source,
            tree.as_ref(),
            &site,
        ),
        Language::CSharp => resolve_analyzer::<CSharpAnalyzer>(analyzer).map_or_else(
            || no_definition("csharp_analyzer_unavailable", "C# analyzer is unavailable"),
            |csharp_analyzer| {
                let definitions = csharp::CSharpDefinitionProvider::new(csharp_analyzer);
                csharp::resolve_csharp(
                    analyzer,
                    &definitions,
                    &request.file,
                    &source,
                    tree.as_ref(),
                    &site,
                )
            },
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
        Language::Ruby => ruby::resolve_ruby(
            analyzer,
            context.support(),
            &request.file,
            &source,
            tree.as_ref(),
            &site,
        ),
        Language::None => {
            unreachable!("unsupported language handled before source extraction")
        }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum QualifiedAccessFocus {
    Qualifier,
    Member,
}

pub(super) fn qualified_access_focus(
    focus: Node<'_>,
    access: Node<'_>,
    qualifier_fields: &[&str],
    member_fields: &[&str],
) -> Option<QualifiedAccessFocus> {
    if fields_contain_focus(access, qualifier_fields, focus) {
        return Some(QualifiedAccessFocus::Qualifier);
    }
    if fields_contain_focus(access, member_fields, focus) {
        return Some(QualifiedAccessFocus::Member);
    }
    None
}

fn fields_contain_focus(access: Node<'_>, fields: &[&str], focus: Node<'_>) -> bool {
    fields.iter().any(|field| {
        access
            .child_by_field_name(field)
            .is_some_and(|child| node_contains_focus(child, focus))
    })
}

pub(super) fn node_contains_focus(node: Node<'_>, focus: Node<'_>) -> bool {
    node.id() == focus.id()
        || (node.start_byte() <= focus.start_byte() && focus.end_byte() <= node.end_byte())
}

pub(crate) fn parse_tree_for_language(
    file: &ProjectFile,
    language: Language,
    source: &str,
) -> Option<Tree> {
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
        Language::Go => go::parse_go_tree(source),
        Language::Ruby => crate::analyzer::ruby::parse_ruby_tree(source),
        Language::None => None,
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
        definitions: candidates,
        lexical_definition: None,
        diagnostics,
    }
}

fn lexical_definition_outcome(definition: LexicalDefinition) -> DefinitionLookupOutcome {
    DefinitionLookupOutcome {
        status: DefinitionLookupStatus::Resolved,
        reference: None,
        definitions: Vec::new(),
        lexical_definition: Some(definition),
        diagnostics: Vec::new(),
    }
}

fn definition_symbol_key(unit: &CodeUnit) -> (String, String) {
    (unit.fq_name(), format!("{:?}", unit.kind()))
}

fn boundary(message: String) -> DefinitionLookupOutcome {
    diagnostic_outcome(
        DefinitionLookupStatus::UnresolvableImportBoundary,
        "unresolvable_import_boundary",
        import_boundary_workspace_message(message),
    )
}

fn import_boundary_workspace_message(message: String) -> String {
    let message = message.replace(
        "outside this partial ",
        "outside the indexed workspace, including this partial ",
    );
    if message.contains("outside the indexed workspace") {
        return message;
    }
    format!(
        "{message}; the imported package, module, namespace, or file may be outside the indexed workspace, including when only a partial workspace is indexed"
    )
}

fn no_definition(kind: impl Into<String>, message: impl Into<String>) -> DefinitionLookupOutcome {
    diagnostic_outcome(DefinitionLookupStatus::NoDefinition, kind, message)
}

fn ambiguous_definition(message: impl Into<String>) -> DefinitionLookupOutcome {
    diagnostic_outcome(
        DefinitionLookupStatus::Ambiguous,
        "ambiguous_definition",
        message,
    )
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
        lexical_definition: None,
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
