use crate::analyzer::common::language_for_file;
use crate::analyzer::lexical_definitions::{
    LexicalBindingResolution, LexicalDefinition, resolve_lexical_binding,
};
use crate::analyzer::usages::cpp_graph::{
    CppDesignatedInitializerOwner, CppLexicalScopeResolution, CppLexicalTypeResolution,
    CppTargetKind, CppVisibilityIndex, cpp_call_arity, cpp_constructor_type_node,
    cpp_designated_initializer_owner, cpp_enclosing_lexical_scope_components,
    cpp_field_declared_type_text, cpp_first_type_child, cpp_function_return_type_text,
    cpp_is_declaration_name, cpp_is_declarator_node, cpp_name_for, cpp_reference_fqn_candidates,
    cpp_signature_arity, cpp_split_top_level_commas, extract_variable_name,
    normalize_cpp_type_text,
};
use crate::analyzer::usages::csharp_graph::{
    csharp_argument_count, csharp_first_type_child, csharp_is_declaration_name,
    csharp_is_type_reference_node, csharp_member_declared_type_fq_name,
    csharp_method_return_type_fq_name_for_arity, csharp_node_text, csharp_object_created_type,
    csharp_object_initializer_for_label, csharp_reference_type_text,
    csharp_visible_extension_method_candidates, member_access_name as csharp_member_access_name,
    member_access_receiver as csharp_member_access_receiver, seed_csharp_bindings_before,
};
use crate::analyzer::usages::go_graph::{
    GoIndexedMemberLookup, GoReferenceResolution, extract_go_import_path,
    go_embedded_field_unit_type_text, go_simple_type_name, go_type_name_parts,
    go_unique_indexed_member_candidate_at_nearest_depth, resolve_go_reference_with_namespaces,
};
use crate::analyzer::usages::inverted_edges::{ClassRangeIndex, first_precise};
use crate::analyzer::usages::java_graph::java_signature_arity;
use crate::analyzer::usages::js_ts_graph::{
    JsTsReceiverFactProvider, JsTsReceiverSyntaxIndex, build_js_ts_receiver_syntax_index,
    cached_jsts_index, compute_jsts_import_binder,
};
use crate::analyzer::usages::local_inference::{
    LocalBindingsSnapshot, LocalInferenceConfig, LocalInferenceEngine,
};
use crate::analyzer::usages::model::{ImportBinder, ImportKind};
use crate::analyzer::usages::php_graph::{
    FileContext, php_node_text, php_qualified_candidate_text, resolve_php_constant,
    resolve_php_function, resolve_php_type,
};
use crate::analyzer::usages::python_graph::{
    collect_assigned_identifiers, collect_module_binding_timeline,
    collect_scope_facts_from_parsed_source, enclosing_scope_facts,
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
    import_candidate_fq_names, import_candidate_owner_fq_names,
    package_name_of as scala_package_name_of, scala_builtin_type_name,
    scala_extension_receiver_matches_resolved, scala_import_path, scala_literal_type_name,
    scala_node_text, scala_normalized_fq_name,
};
use crate::analyzer::{
    AliasResolver, AnalyzerDefinitionLookup, AnalyzerQueryScope, BoundedDefinitionLookup,
    CSharpAnalyzer, CodeUnit, CppAnalyzer, GoAnalyzer, IAnalyzer, ImportAnalysisProvider,
    ImportInfo, JavaAnalyzer, Language, ModuleBindingEventKind, ModuleBindingTimeline, PhpAnalyzer,
    ProjectFile, PythonAnalyzer, Range, RubyAnalyzer, RustAnalyzer, ScalaAnalyzer,
    cpp_include_paths, cpp_node_text, csharp_callable_arity, resolve_analyzer,
    resolve_include_targets,
};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};
use crate::path_utils::rel_path_string;
use crate::profiling;
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
pub(crate) use rust::{
    AnalyzerRustDefinitionProvider, RustTypeLookupCache,
    rust_expression_type_definition_fqn_cached, rust_is_type_definition,
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
    CallSiteSyntax, CallSyntaxKind, call_reference_ranges_in_tree, call_signature_context,
    call_site_syntax_for_reference, is_call_reference_range_in_tree,
};
pub(crate) use csharp::{CSharpTypeLookupResolution, csharp_type_lookup_resolution};
pub(crate) use go::{
    AnalyzerGoDefinitionProvider, GoDefinitionProvider, GoTypeLookupResolutionKind,
    go_type_lookup_resolution,
};
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
    let _scope = profiling::scope("get_definition::resolve_definition_batch");
    if profiling::enabled() {
        profiling::note(format!("request_count={}", requests.len()));
    }
    let mut context = DefinitionBatchContext::new(analyzer, requests.len() > 1);
    resolve_definition_requests(analyzer, &mut context, requests, None)
}

fn resolve_definition_requests(
    analyzer: &dyn IAnalyzer,
    context: &mut DefinitionBatchContext<'_>,
    requests: Vec<DefinitionLookupRequest>,
    cancellation: Option<&CancellationToken>,
) -> Vec<DefinitionLookupOutcome> {
    let _query_scope = AnalyzerQueryScope::new(analyzer);
    let mut remaining_python_requests: HashMap<ProjectFile, usize> = HashMap::default();
    for request in &requests {
        if language_for_file(&request.file) == Language::Python {
            *remaining_python_requests
                .entry(request.file.clone())
                .or_default() += 1;
        }
    }

    requests
        .into_iter()
        .take_while(|_| !cancellation.is_some_and(CancellationToken::is_cancelled))
        .map(|request| {
            let is_python = language_for_file(&request.file) == Language::Python;
            let file = request.file.clone();
            let outcome = resolve_one(analyzer, context, request);
            if is_python && let Some(remaining) = remaining_python_requests.get_mut(&file) {
                *remaining -= 1;
                if *remaining == 0 {
                    context.python_contexts.remove(&file);
                }
            }
            outcome
        })
        .collect()
}

pub(crate) fn resolve_definition_batch_with_source(
    analyzer: &dyn IAnalyzer,
    requests: Vec<DefinitionLookupRequest>,
    file: ProjectFile,
    source: Arc<String>,
) -> Vec<DefinitionLookupOutcome> {
    let mut context = DefinitionBatchContext::new(analyzer, requests.len() > 1);
    context.sources.insert(file, Ok(source));
    resolve_definition_requests(analyzer, &mut context, requests, None)
}

pub(crate) fn resolve_definition_batch_with_source_and_cancellation(
    analyzer: &dyn IAnalyzer,
    requests: Vec<DefinitionLookupRequest>,
    file: ProjectFile,
    source: Arc<String>,
    cancellation: &CancellationToken,
) -> Vec<DefinitionLookupOutcome> {
    let mut context = DefinitionBatchContext::new(analyzer, requests.len() > 1);
    context.sources.insert(file, Ok(source));
    resolve_definition_requests(analyzer, &mut context, requests, Some(cancellation))
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

    let mut context = DefinitionBatchContext::new(analyzer, false);
    context.sources.insert(file, Ok(source));
    let source = context.source(&request.file).ok()?;
    let tree = context.tree(&request.file, language, &source)?;
    if !is_call_reference_range_in_tree(&tree, language, start_byte, end_byte) {
        return None;
    }

    Some(resolve_one(analyzer, &mut context, request))
}

#[derive(Clone)]
pub(super) struct JsTsDefinitionContext {
    pub(super) imports: ImportBinder,
    pub(super) aliases: Arc<AliasResolver>,
    pub(super) syntax_index: Arc<JsTsReceiverSyntaxIndex>,
}

#[derive(Clone)]
struct GoDefinitionContext {
    package: String,
    aliases: HashMap<String, Vec<String>>,
    dot_imports: Vec<String>,
}

#[derive(Clone)]
pub(super) struct ScalaDefinitionContext {
    pub(super) package: Arc<str>,
    pub(super) imports: Arc<Vec<ImportInfo>>,
}

struct DefinitionBatchContext<'a> {
    analyzer: &'a dyn IAnalyzer,
    bounded_support: AnalyzerDefinitionLookup<'a>,
    rust_support: Option<rust::AnalyzerRustDefinitionProvider<'a>>,
    rust_type_cache: RustTypeLookupCache,
    js_ts_contexts: HashMap<(ProjectFile, Language), JsTsDefinitionContext>,
    go_contexts: HashMap<ProjectFile, GoDefinitionContext>,
    scala_contexts: HashMap<ProjectFile, ScalaDefinitionContext>,
    sources: HashMap<ProjectFile, Result<Arc<String>, String>>,
    trees: HashMap<(ProjectFile, Language), Option<Tree>>,
    line_starts: HashMap<ProjectFile, Arc<Vec<usize>>>,
    cpp_visibility: HashMap<ProjectFile, Arc<CppVisibilityIndex>>,
    // Candidate declaration ranges belong to the analyzer generation, so these
    // caches must use indexed source rather than the request's live disk source.
    cpp_indexed_sources: HashMap<ProjectFile, Option<Arc<String>>>,
    cpp_indexed_trees: HashMap<ProjectFile, Option<Tree>>,
    cpp_structural_alias_paths: HashMap<CodeUnit, Vec<String>>,
    cpp_class_ranges: HashMap<ProjectFile, Arc<ClassRangeIndex>>,
    cpp_enclosing_class_chains: HashMap<CodeUnit, Arc<Vec<CodeUnit>>>,
    python_contexts: HashMap<ProjectFile, Arc<python::PythonDefinitionContext>>,
    #[cfg(test)]
    cpp_class_range_builds: usize,
    #[cfg(test)]
    python_build_counters: Arc<python::PythonDefinitionBuildCounters>,
}

impl<'a> DefinitionBatchContext<'a> {
    fn new(analyzer: &'a dyn IAnalyzer, cache_rust_lookups: bool) -> Self {
        Self {
            analyzer,
            bounded_support: AnalyzerDefinitionLookup::new(analyzer, Language::None),
            rust_support: resolve_analyzer::<RustAnalyzer>(analyzer)
                .map(|rust| rust::AnalyzerRustDefinitionProvider::new(rust, cache_rust_lookups)),
            rust_type_cache: RustTypeLookupCache::default(),
            js_ts_contexts: HashMap::default(),
            go_contexts: HashMap::default(),
            scala_contexts: HashMap::default(),
            sources: HashMap::default(),
            trees: HashMap::default(),
            line_starts: HashMap::default(),
            cpp_visibility: HashMap::default(),
            cpp_indexed_sources: HashMap::default(),
            cpp_indexed_trees: HashMap::default(),
            cpp_structural_alias_paths: HashMap::default(),
            cpp_class_ranges: HashMap::default(),
            cpp_enclosing_class_chains: HashMap::default(),
            python_contexts: HashMap::default(),
            #[cfg(test)]
            cpp_class_range_builds: 0,
            #[cfg(test)]
            python_build_counters: Arc::default(),
        }
    }

    fn bounded_support(&self) -> &dyn BoundedDefinitionLookup {
        &self.bounded_support
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

    fn js_ts_context(
        &mut self,
        file: &ProjectFile,
        language: Language,
        source: &str,
        tree: &Tree,
    ) -> JsTsDefinitionContext {
        self.js_ts_contexts
            .entry((file.clone(), language))
            .or_insert_with(|| {
                let (syntax_index, _) =
                    build_js_ts_receiver_syntax_index(tree.root_node(), source, None)
                        .expect("uncancelled JS/TS syntax index build");
                JsTsDefinitionContext {
                    imports: compute_jsts_import_binder(source, tree),
                    aliases: Arc::new(AliasResolver::new(
                        self.analyzer.project().root().to_path_buf(),
                    )),
                    syntax_index,
                }
            })
            .clone()
    }

    fn go_context(
        &mut self,
        go: &GoAnalyzer,
        file: &ProjectFile,
        source: &str,
        tree: &Tree,
    ) -> &GoDefinitionContext {
        self.go_contexts.entry(file.clone()).or_insert_with(|| {
            let (aliases, dot_imports) = go.definition_import_namespaces(file);
            GoDefinitionContext {
                package: go.canonical_package_name_from_tree(file, source, tree.root_node()),
                aliases,
                dot_imports,
            }
        })
    }

    fn scala_context(
        &mut self,
        scala: &ScalaAnalyzer,
        file: &ProjectFile,
    ) -> ScalaDefinitionContext {
        self.scala_contexts
            .entry(file.clone())
            .or_insert_with(|| ScalaDefinitionContext {
                package: Arc::from(scala_package_name_of(scala, file).unwrap_or_default()),
                imports: Arc::new(scala.import_info_of(file)),
            })
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

    fn cpp_indexed_source(&mut self, file: &ProjectFile) -> Option<Arc<String>> {
        self.cpp_indexed_sources
            .entry(file.clone())
            .or_insert_with(|| self.analyzer.indexed_source(file).map(Arc::new))
            .clone()
    }

    fn cpp_indexed_tree(&mut self, file: &ProjectFile) -> Option<Tree> {
        if let Some(tree) = self.cpp_indexed_trees.get(file) {
            return tree.clone();
        }
        let parsed = self
            .cpp_indexed_source(file)
            .and_then(|source| cpp::parse_cpp_tree(&source));
        self.cpp_indexed_trees.insert(file.clone(), parsed.clone());
        parsed
    }

    fn cpp_class_ranges(&mut self, file: &ProjectFile) -> Arc<ClassRangeIndex> {
        if let Some(index) = self.cpp_class_ranges.get(file) {
            return Arc::clone(index);
        }
        let index = Arc::new(ClassRangeIndex::build(self.analyzer, file));
        self.cpp_class_ranges
            .insert(file.clone(), Arc::clone(&index));
        #[cfg(test)]
        {
            self.cpp_class_range_builds += 1;
        }
        index
    }

    fn cpp_enclosing_class_chain(&mut self, owner: CodeUnit) -> Arc<Vec<CodeUnit>> {
        self.cpp_enclosing_class_chains
            .entry(owner.clone())
            .or_insert_with(|| {
                let mut classes = Vec::new();
                let mut current = Some(owner);
                while let Some(owner) = current {
                    if !owner.is_class() {
                        break;
                    }
                    current = self.analyzer.parent_of(&owner);
                    classes.push(owner);
                }
                Arc::new(classes)
            })
            .clone()
    }

    fn python_context(
        &mut self,
        py: &PythonAnalyzer,
        file: &ProjectFile,
    ) -> Arc<python::PythonDefinitionContext> {
        self.python_contexts
            .entry(file.clone())
            .or_insert_with(|| {
                let _scope = crate::profiling::scope("get_definition::python::batch_context");
                #[cfg(test)]
                self.python_build_counters
                    .context_builds
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Arc::new(python::PythonDefinitionContext::build(
                    py,
                    self.analyzer,
                    file,
                    #[cfg(test)]
                    Arc::clone(&self.python_build_counters),
                ))
            })
            .clone()
    }

    #[cfg(test)]
    fn python_build_counts(&self) -> (usize, usize, usize, usize) {
        (
            self.python_build_counters
                .context_builds
                .load(std::sync::atomic::Ordering::Relaxed),
            self.python_build_counters
                .scope_fact_builds
                .load(std::sync::atomic::Ordering::Relaxed),
            self.python_build_counters
                .receiver_type_cache_misses
                .load(std::sync::atomic::Ordering::Relaxed),
            self.python_build_counters
                .generic_receiver_type_fallbacks
                .load(std::sync::atomic::Ordering::Relaxed),
        )
    }
}

fn resolve_one(
    analyzer: &dyn IAnalyzer,
    context: &mut DefinitionBatchContext<'_>,
    request: DefinitionLookupRequest,
) -> DefinitionLookupOutcome {
    let _scope = profiling::scope("get_definition::resolve_one");
    let language = language_for_file(&request.file);
    context.bounded_support.set_language(language);
    if profiling::enabled() {
        profiling::note(format!("language={language:?}"));
    }
    if matches!(language, Language::None) {
        return diagnostic_outcome(
            DefinitionLookupStatus::UnsupportedLanguage,
            "unsupported_language",
            format!("{language:?} get_definition is not implemented yet"),
        );
    }

    let source = {
        let _scope = profiling::scope("get_definition::source");
        match context.source(&request.file) {
            Ok(source) => source,
            Err(message) => {
                return diagnostic_outcome(
                    DefinitionLookupStatus::NotFound,
                    "file_read_failed",
                    message,
                );
            }
        }
    };

    let site = {
        let _scope = profiling::scope("get_definition::reference_site");
        let line_starts = context.line_starts(&request.file, &source);
        match resolve_reference_site_with_line_starts(
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
        }
    };
    let site = if matches!(language, Language::JavaScript | Language::TypeScript) {
        js_ts::jsts_site_for_focus(site)
    } else {
        site
    };

    let tree = {
        let _scope = profiling::scope("get_definition::parse_tree");
        context.tree(&request.file, language, &source)
    };
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
    let _dispatch_scope = profiling::scope("get_definition::language_dispatch");
    let resolved = match language {
        Language::Rust => {
            let (rust_support, rust_type_cache) =
                (&context.rust_support, &mut context.rust_type_cache);
            rust_support.as_ref().map_or_else(
                || no_definition("rust_analyzer_unavailable", "Rust analyzer is unavailable"),
                |support| {
                    rust::resolve_rust(
                        analyzer,
                        support,
                        &request.file,
                        &source,
                        tree.as_ref(),
                        &site,
                        rust_type_cache,
                    )
                },
            )
        }
        Language::JavaScript | Language::TypeScript => js_ts::resolve_js_ts(
            analyzer,
            context,
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
                let batch = context.go_context(go, &request.file, &source, tree);
                Some(resolve_go_reference_with_namespaces(
                    tree.root_node(),
                    &source,
                    &batch.package,
                    &batch.aliases,
                    &batch.dot_imports,
                    &site,
                ))
            });
            if let Some(go_analyzer) = go {
                go::resolve_go(
                    analyzer,
                    &go::AnalyzerGoDefinitionProvider::new(go_analyzer),
                    &request.file,
                    &source,
                    tree.as_ref(),
                    &site,
                    resolution,
                )
            } else {
                no_definition("go_analyzer_unavailable", "Go analyzer is unavailable")
            }
        }
        Language::Java => java::resolve_java(
            analyzer,
            context.bounded_support(),
            &request.file,
            &source,
            tree.as_ref(),
            &site,
        ),
        Language::Php => php::resolve_php(
            analyzer,
            context.bounded_support(),
            &request.file,
            &source,
            tree.as_ref(),
            &site,
        ),
        Language::Python => python::resolve_python(
            analyzer,
            context,
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
            context.bounded_support(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{Project, TestProject};
    use crate::test_support::AnalyzerFixture;

    #[test]
    fn python_batch_context_builds_file_and_scope_state_once() {
        let source = "from service import Service\n\ndef handle(service: Service):\n    service.run()\n    service.stop()\n";
        let fixture = AnalyzerFixture::new_for_language(
            Language::Python,
            &[
                (
                    "service.py",
                    "class Service:\n    def run(self):\n        pass\n\n    def stop(self):\n        pass\n",
                ),
                ("app.py", source),
            ],
        );
        let file = ProjectFile::new(fixture.project_root(), "app.py");
        let analyzer = fixture.analyzer.analyzer();
        analyzer.reset_global_usage_definition_index_build_count_for_test();
        analyzer.reset_full_declaration_scan_count_for_test();
        let mut context = DefinitionBatchContext::new(analyzer, true);
        let requests = ["run", "stop"]
            .into_iter()
            .map(|needle| {
                let start_byte = source.rfind(needle).expect("receiver member in source");
                DefinitionLookupRequest {
                    file: file.clone(),
                    line: None,
                    column: None,
                    start_byte: Some(start_byte),
                    end_byte: Some(start_byte + needle.len()),
                }
            })
            .collect::<Vec<_>>();

        let outcomes = resolve_definition_requests(analyzer, &mut context, requests, None);

        assert!(outcomes.iter().all(|outcome| {
            outcome.status == DefinitionLookupStatus::Resolved
                && outcome.definitions[0]
                    .fq_name()
                    .starts_with("service.Service.")
        }));
        assert_eq!(context.python_build_counts(), (1, 1, 1, 0));
        assert_eq!(
            analyzer.global_usage_definition_index_build_count_for_test(),
            0
        );
        assert_eq!(analyzer.full_declaration_scan_count_for_test(), 0);
        assert!(context.python_contexts.is_empty());
    }

    #[test]
    fn rust_batch_context_reuses_parsed_declaration_source_for_repeated_field_lookups() {
        let source = "struct Inner { value: i32 }\nstruct Outer { inner: Inner }\nfn first(outer: Outer) -> i32 { outer.inner.value }\nfn second(outer: Outer) -> i32 { outer.inner.value }\n";
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, &[("src/lib.rs", source)]);
        let file = ProjectFile::new(fixture.project_root(), "src/lib.rs");
        let analyzer = fixture.analyzer.analyzer();
        let mut context = DefinitionBatchContext::new(analyzer, true);
        let requests = source
            .match_indices("value")
            .skip(1)
            .map(|(start_byte, reference)| DefinitionLookupRequest {
                file: file.clone(),
                line: None,
                column: None,
                start_byte: Some(start_byte),
                end_byte: Some(start_byte + reference.len()),
            })
            .collect();

        let outcomes = resolve_definition_requests(analyzer, &mut context, requests, None);

        assert!(outcomes.iter().all(|outcome| {
            outcome.status == DefinitionLookupStatus::Resolved
                && outcome
                    .definitions
                    .iter()
                    .any(|unit| unit.fq_name() == "Inner.value")
        }));
        assert_eq!(
            context
                .rust_type_cache
                .parsed_declaration_source_count_for_test(),
            1,
            "one definition batch should parse each Rust declaration source once"
        );
    }

    #[test]
    fn js_ts_batch_context_reuses_import_alias_and_receiver_syntax_state() {
        let source = "import { Value } from './value';\nconst first: Value = {} as Value;\nconst second: Value = {} as Value;\n";
        let fixture = AnalyzerFixture::new_for_language(
            Language::TypeScript,
            &[
                ("value.ts", "export class Value {}\n"),
                ("consumer.ts", source),
            ],
        );
        let file = ProjectFile::new(fixture.project_root(), "consumer.ts");
        let analyzer = fixture.analyzer.analyzer();
        let tree = parse_tree_for_language(&file, Language::TypeScript, source)
            .expect("parse TypeScript source");
        let mut context = DefinitionBatchContext::new(analyzer, true);

        let first = context.js_ts_context(&file, Language::TypeScript, source, &tree);
        let second = context.js_ts_context(&file, Language::TypeScript, source, &tree);

        assert_eq!(context.js_ts_contexts.len(), 1);
        assert!(Arc::ptr_eq(&first.aliases, &second.aliases));
        assert!(Arc::ptr_eq(&first.syntax_index, &second.syntax_index));
        assert_eq!(first.imports.bindings, second.imports.bindings);
    }

    #[test]
    fn go_batch_context_reuses_package_and_import_namespaces() {
        let source =
            "package consumer\nimport dep \"example.com/dep\"\nfunc run() { dep.Call() }\n";
        let fixture = AnalyzerFixture::new_for_language(Language::Go, &[("consumer.go", source)]);
        let file = ProjectFile::new(fixture.project_root(), "consumer.go");
        let analyzer = fixture.analyzer.analyzer();
        let go = resolve_analyzer::<GoAnalyzer>(analyzer).expect("Go analyzer");
        let tree = parse_tree_for_language(&file, Language::Go, source).expect("parse Go source");
        let mut context = DefinitionBatchContext::new(analyzer, true);

        {
            let first = context.go_context(go, &file, source, &tree);
            assert_eq!(first.package, "consumer");
            assert_eq!(first.aliases.len(), 1);
        }
        let second_aliases = {
            let second = context.go_context(go, &file, source, &tree);
            assert_eq!(second.package, "consumer");
            second.aliases.len()
        };
        assert_eq!(context.go_contexts.len(), 1);
        assert_eq!(second_aliases, 1);
    }

    #[test]
    fn scala_batch_context_reuses_package_and_import_facts() {
        let source =
            "package demo\nimport demo.shared.Widget\nobject Main { val widget = new Widget }\n";
        let fixture = AnalyzerFixture::new_for_language(
            Language::Scala,
            &[
                ("shared.scala", "package demo.shared\nclass Widget\n"),
                ("main.scala", source),
            ],
        );
        let file = ProjectFile::new(fixture.project_root(), "main.scala");
        let analyzer = fixture.analyzer.analyzer();
        let scala = resolve_analyzer::<ScalaAnalyzer>(analyzer).expect("Scala analyzer");
        let mut context = DefinitionBatchContext::new(analyzer, true);

        let first = context.scala_context(scala, &file);
        let second = context.scala_context(scala, &file);

        assert_eq!(context.scala_contexts.len(), 1);
        assert_eq!(first.package.as_ref(), "demo");
        assert_eq!(first.imports, second.imports);
    }

    #[test]
    fn python_batch_context_resolves_explicit_reexports_without_generic_imports() {
        let source =
            "from facade import Service\n\ndef handle(service: Service):\n    service.run()\n";
        let fixture = AnalyzerFixture::new_for_language(
            Language::Python,
            &[
                (
                    "service.py",
                    "class Service:\n    def run(self):\n        pass\n",
                ),
                ("facade.py", "from service import Service\n"),
                ("app.py", source),
            ],
        );
        let file = ProjectFile::new(fixture.project_root(), "app.py");
        let analyzer = fixture.analyzer.analyzer();
        let mut context = DefinitionBatchContext::new(analyzer, true);
        let start_byte = source.rfind("run").expect("receiver member in source");

        let outcomes = resolve_definition_requests(
            analyzer,
            &mut context,
            vec![DefinitionLookupRequest {
                file,
                line: None,
                column: None,
                start_byte: Some(start_byte),
                end_byte: Some(start_byte + "run".len()),
            }],
            None,
        );

        assert_eq!(outcomes[0].status, DefinitionLookupStatus::Resolved);
        assert_eq!(outcomes[0].definitions[0].fq_name(), "service.Service.run");
        assert_eq!(context.python_build_counts(), (1, 1, 1, 0));
        assert!(context.python_contexts.is_empty());
    }

    #[test]
    fn python_batch_context_preserves_reexport_source_order_across_facades() {
        let source = "from facade_import_wins import Service as ImportedWins\nfrom facade_local_wins import Service as LocalWins\n\ndef handle(imported: ImportedWins, local: LocalWins):\n    imported.leaf_only()\n    local.local_only()\n";
        let fixture = AnalyzerFixture::new_for_language(
            Language::Python,
            &[
                (
                    "leaf.py",
                    "class Service:\n    def leaf_only(self):\n        pass\n",
                ),
                (
                    "middle_import_wins.py",
                    "class Service:\n    pass\n\nfrom leaf import Service\n",
                ),
                (
                    "middle_local_wins.py",
                    "from leaf import Service\n\nclass Service:\n    def local_only(self):\n        pass\n",
                ),
                (
                    "facade_import_wins.py",
                    "from middle_import_wins import Service\n",
                ),
                (
                    "facade_local_wins.py",
                    "from middle_local_wins import Service\n",
                ),
                ("app.py", source),
            ],
        );
        let file = ProjectFile::new(fixture.project_root(), "app.py");
        let analyzer = fixture.analyzer.analyzer();
        let mut context = DefinitionBatchContext::new(analyzer, true);
        let requests = ["leaf_only", "local_only"]
            .into_iter()
            .map(|needle| {
                let start_byte = source.rfind(needle).expect("receiver member in source");
                DefinitionLookupRequest {
                    file: file.clone(),
                    line: None,
                    column: None,
                    start_byte: Some(start_byte),
                    end_byte: Some(start_byte + needle.len()),
                }
            })
            .collect();

        let outcomes = resolve_definition_requests(analyzer, &mut context, requests, None);

        assert_eq!(
            outcomes[0].definitions[0].fq_name(),
            "leaf.Service.leaf_only"
        );
        assert_eq!(
            outcomes[1].definitions[0].fq_name(),
            "middle_local_wins.Service.local_only"
        );
        assert_eq!(context.python_build_counts(), (1, 1, 2, 0));
        assert!(context.python_contexts.is_empty());
    }

    #[test]
    fn python_batch_context_keeps_receiver_types_isolated_by_file() {
        let source_a =
            "from service_a import Service\n\ndef handle(service: Service):\n    service.run()\n";
        let source_b =
            "from service_b import Service\n\ndef handle(service: Service):\n    service.stop()\n";
        let fixture = AnalyzerFixture::new_for_language(
            Language::Python,
            &[
                (
                    "service_a.py",
                    "class Service:\n    def run(self):\n        pass\n",
                ),
                (
                    "service_b.py",
                    "class Service:\n    def stop(self):\n        pass\n",
                ),
                ("app_a.py", source_a),
                ("app_b.py", source_b),
            ],
        );
        let file_a = ProjectFile::new(fixture.project_root(), "app_a.py");
        let file_b = ProjectFile::new(fixture.project_root(), "app_b.py");
        let analyzer = fixture.analyzer.analyzer();
        let mut context = DefinitionBatchContext::new(analyzer, true);
        let requests = [(file_a, source_a, "run"), (file_b, source_b, "stop")]
            .into_iter()
            .map(|(file, source, needle)| {
                let start_byte = source.rfind(needle).expect("receiver member in source");
                DefinitionLookupRequest {
                    file,
                    line: None,
                    column: None,
                    start_byte: Some(start_byte),
                    end_byte: Some(start_byte + needle.len()),
                }
            })
            .collect();

        let outcomes = resolve_definition_requests(analyzer, &mut context, requests, None);

        assert_eq!(
            outcomes[0].definitions[0].fq_name(),
            "service_a.Service.run"
        );
        assert_eq!(
            outcomes[1].definitions[0].fq_name(),
            "service_b.Service.stop"
        );
        assert_eq!(context.python_build_counts(), (2, 2, 2, 0));
        assert!(context.python_contexts.is_empty());
    }

    #[test]
    fn python_batch_receiver_type_cache_bypasses_inserts_at_its_limit() {
        let source = "from service import Service\nfrom other import Other\n\ndef handle(service: Service, other: Other):\n    service.run()\n    other.stop()\n    service.run()\n";
        let fixture = AnalyzerFixture::new_for_language(
            Language::Python,
            &[
                (
                    "service.py",
                    "class Service:\n    def run(self):\n        pass\n",
                ),
                (
                    "other.py",
                    "class Other:\n    def stop(self):\n        pass\n",
                ),
                ("app.py", source),
            ],
        );
        let file = ProjectFile::new(fixture.project_root(), "app.py");
        let analyzer = fixture.analyzer.analyzer();
        let py = resolve_analyzer::<PythonAnalyzer>(analyzer).expect("Python analyzer");
        let mut context = DefinitionBatchContext::new(analyzer, true);
        let python_context = context.python_context(py, &file);
        python_context.set_receiver_type_cache_limit(1);
        let member_offsets = [
            source
                .find("service.run")
                .expect("first service call in source")
                + "service.".len(),
            source.find("other.stop").expect("other call in source") + "other.".len(),
            source
                .rfind("service.run")
                .expect("second service call in source")
                + "service.".len(),
        ];
        let requests = member_offsets
            .into_iter()
            .zip(["run", "stop", "run"])
            .map(|(start_byte, needle)| DefinitionLookupRequest {
                file: file.clone(),
                line: None,
                column: None,
                start_byte: Some(start_byte),
                end_byte: Some(start_byte + needle.len()),
            })
            .collect();

        let outcomes = resolve_definition_requests(analyzer, &mut context, requests, None);

        assert_eq!(outcomes[0].definitions[0].fq_name(), "service.Service.run");
        assert_eq!(outcomes[1].definitions[0].fq_name(), "other.Other.stop");
        assert_eq!(outcomes[2].definitions[0].fq_name(), "service.Service.run");
        assert_eq!(python_context.receiver_type_cache_len(), 1);
        assert_eq!(context.python_build_counts(), (1, 1, 2, 0));
        assert!(context.python_contexts.is_empty());
    }

    #[test]
    fn cpp_focused_qualifiers_build_class_ranges_once_per_file() {
        const REFERENCE_COUNT: usize = 32;
        const UNRELATED_CLASSES: usize = 128;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let consumer = ProjectFile::new(root.clone(), "consumer.cpp");
        let mut source = String::new();
        for index in 0..UNRELATED_CLASSES {
            source.push_str(&format!("struct Unrelated{index} {{ int value; }};\n"));
        }
        source.push_str("struct Host { void exercise() {\n");
        for _ in 0..REFERENCE_COUNT {
            source.push_str("  Unknown::BindOnce();\n");
        }
        source.push_str("} };\n");
        consumer.write(&source).unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Cpp));
        let analyzer = CppAnalyzer::new(project);
        let requests = source
            .match_indices("Unknown")
            .map(|(start_byte, name)| DefinitionLookupRequest {
                file: consumer.clone(),
                line: None,
                column: None,
                start_byte: Some(start_byte),
                end_byte: Some(start_byte + name.len()),
            })
            .collect::<Vec<_>>();
        let mut context = DefinitionBatchContext::new(&analyzer, true);

        let outcomes = resolve_definition_requests(&analyzer, &mut context, requests, None);

        assert_eq!(outcomes.len(), REFERENCE_COUNT);
        assert!(outcomes.iter().all(|outcome| {
            outcome.status == DefinitionLookupStatus::NoDefinition && outcome.definitions.is_empty()
        }));
        assert_eq!(
            context.cpp_class_range_builds, 1,
            "focused qualifiers in one file should share one class-range index"
        );
        assert_eq!(
            context.cpp_enclosing_class_chains.len(),
            1,
            "focused qualifiers in one class should share its enclosing owner chain"
        );
    }

    #[test]
    fn cpp_definition_batch_validates_each_candidate_file_once_per_batch() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let types = ProjectFile::new(root.clone(), "types.hpp");
        let consumer = ProjectFile::new(root.clone(), "consumer.cpp");
        types.write("using Size = unsigned long;\n").unwrap();
        let source = "#include \"types.hpp\"\nSize first;\nSize second;\n";
        consumer.write(source).unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Cpp));
        let analyzer = CppAnalyzer::new(project);
        analyzer.reset_live_oid_validation_counts_for_test();
        let requests = source
            .match_indices("Size")
            .map(|(start_byte, name)| DefinitionLookupRequest {
                file: consumer.clone(),
                line: None,
                column: None,
                start_byte: Some(start_byte),
                end_byte: Some(start_byte + name.len()),
            })
            .collect::<Vec<_>>();

        let first = resolve_definition_batch_with_source(
            &analyzer,
            requests.clone(),
            consumer.clone(),
            Arc::new(source.to_string()),
        );
        let first_batch_validations = analyzer.live_oid_validation_count_for_test(&types);
        let second = resolve_definition_batch_with_source(
            &analyzer,
            vec![requests[0].clone()],
            consumer,
            Arc::new(source.to_string()),
        );
        let after_second_batch = analyzer.live_oid_validation_count_for_test(&types);

        assert!(first.iter().all(|outcome| {
            outcome.status == DefinitionLookupStatus::Resolved
                && outcome
                    .definitions
                    .iter()
                    .any(|unit| unit.short_name() == "Size")
        }));
        assert_eq!(second[0].status, DefinitionLookupStatus::Resolved);
        assert_eq!(
            (
                first_batch_validations,
                after_second_batch.saturating_sub(first_batch_validations),
            ),
            (1, 1),
            "reuse validation within one batch, then revalidate once in a separate batch"
        );
    }

    #[test]
    fn cpp_type_definition_routing_classifies_only_name_bounded_candidates() {
        const UNRELATED_DECLARATIONS: usize = 128;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let types = ProjectFile::new(root.clone(), "types.hpp");
        let consumer = ProjectFile::new(root.clone(), "consumer.cpp");
        let mut header = "namespace ns { struct Target { void run(); }; }\n".to_string();
        for index in 0..UNRELATED_DECLARATIONS / 2 {
            header.push_str(&format!("int unrelated_function_{index}();\n"));
            header.push_str(&format!("using UnrelatedAlias{index} = unsigned long;\n"));
        }
        types.write(&header).unwrap();
        let source = "#include \"types.hpp\"\nnamespace ns { void local_case() { Target local; local.run(); } }\nvoid qualified_case() { ns::Target qualified; qualified.run(); }\n";
        consumer.write(source).unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Cpp));
        let analyzer = CppAnalyzer::new(project);
        analyzer.reset_type_alias_classification_count_for_test();
        let requests = source
            .match_indices("run")
            .map(|(start_byte, name)| DefinitionLookupRequest {
                file: consumer.clone(),
                line: None,
                column: None,
                start_byte: Some(start_byte),
                end_byte: Some(start_byte + name.len()),
            })
            .collect::<Vec<_>>();

        let first = resolve_definition_batch_with_source(
            &analyzer,
            requests.clone(),
            consumer.clone(),
            Arc::new(source.to_string()),
        );
        let first_batch_classifications = analyzer.type_alias_classification_count_for_test();
        let second = resolve_definition_batch_with_source(
            &analyzer,
            vec![requests[1].clone()],
            consumer,
            Arc::new(source.to_string()),
        );
        let second_batch_classifications = analyzer
            .type_alias_classification_count_for_test()
            .saturating_sub(first_batch_classifications);
        for outcome in first.iter().chain(&second) {
            assert_eq!(outcome.status, DefinitionLookupStatus::Resolved);
            assert!(
                outcome
                    .definitions
                    .iter()
                    .any(|unit| unit.short_name() == "Target.run" && unit.package_name() == "ns")
            );
        }
        assert!(
            first_batch_classifications <= requests.len() * 10
                && second_batch_classifications <= 10,
            "provider-backed alias classification must scale with named requests, not {UNRELATED_DECLARATIONS} unrelated visible declarations: first={first_batch_classifications}, second={second_batch_classifications}"
        );
    }
}
