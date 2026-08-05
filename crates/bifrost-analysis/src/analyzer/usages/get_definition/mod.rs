use crate::analyzer::common::language_for_file;
use crate::analyzer::js_ts::syntax::JsTsImportBinder;
use crate::analyzer::lexical_definitions::{
    LexicalBindingResolution, LexicalDefinition, resolve_lexical_binding,
};
use crate::analyzer::structural::resolution::{BoundaryStatus, PrecedenceTier, RejectionReason};
use crate::analyzer::usages::common::namespace_prefixes;
use crate::analyzer::usages::cpp_graph::{
    CallArityEvidence, CppBareCallTargetResolution, CppDesignatedInitializerOwner,
    CppLexicalScopeResolution, CppLexicalTypeResolution, CppTargetKind, CppVisibilityIndex,
    cpp_argument_children, cpp_constructor_type_node, cpp_designated_initializer_owner,
    cpp_enclosing_lexical_scope_components, cpp_field_declared_type_binding, cpp_first_type_child,
    cpp_function_return_type_text, cpp_initialized_effective_using_imports,
    cpp_is_declaration_name, cpp_is_declarator_node, cpp_name_for, cpp_reference_fqn_candidates,
    cpp_resolve_bare_call_target, cpp_signature_arity, cpp_split_top_level_commas,
    cpp_template_reference_arguments, cpp_type_name_components, extract_variable_name,
    is_globally_qualified_cpp_name, normalize_cpp_type_text,
};
use crate::analyzer::usages::csharp_graph::{
    csharp_argument_count, csharp_extension_invocation_return_type_fq_name,
    csharp_first_type_child, csharp_is_declaration_name, csharp_is_type_reference_node,
    csharp_member_declared_type_fq_name, csharp_method_return_type_fq_name_for_arity,
    csharp_node_text, csharp_object_created_type, csharp_object_initializer_for_label,
    csharp_object_initializer_owner_type_node, csharp_reference_type_text,
    csharp_visible_extension_method_candidates, member_access_name as csharp_member_access_name,
    member_access_receiver as csharp_member_access_receiver, seed_csharp_bindings_before,
};
use crate::analyzer::usages::go_graph::{
    GoReferenceResolution, GoSelectorDescriptor, go_selector_descriptor,
    go_selector_descriptor_with_scope, go_simple_type_name, go_type_name_parts,
    resolve_go_reference_with_namespaces,
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
    resolve_receiver_type as resolve_python_receiver_type, with_python_graph_source,
};
use crate::analyzer::usages::receiver_analysis::{ReceiverAnalysisBudget, ReceiverAnalysisOutcome};
pub(crate) use crate::analyzer::usages::reference_site::byte_offset_for_character_column;
pub(crate) use crate::analyzer::usages::reference_site::{
    ResolvedReferenceSite, SourceLocationRequest, resolve_reference_site_with_line_starts,
    smallest_named_node_covering,
};
// The Ruby definition route is parked on `ResolutionSession`'s siblings while
// `ruby_graph/*` has moved into `brokk-bifrost-ruby`, so this block -- the
// fleet's largest reach-in into a language's graph module -- inverts through the
// crate. The direction is one-way, exactly as it is for rust and python:
// `brokk_bifrost_ruby::graph` names `ResolutionSession`, `get_definition`,
// `get_type` and `DefinitionBatchContext` zero times.
use crate::analyzer::usages::scala_graph::syntax::ScalaPackageContextIndex;
use crate::analyzer::usages::scala_graph::{
    import_candidate_fq_names, import_candidate_owner_fq_names,
    package_name_of as scala_package_name_of, scala_builtin_type_name,
    scala_extension_receiver_matches_resolved, scala_literal_type_name, scala_node_text,
    scala_normalized_fq_name,
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
use crate::navigation::NavigationOperation;
use crate::path_utils::rel_path_string;
use crate::profiling;
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
use brokk_bifrost_ruby::graph::RubyGraphSource;
use brokk_bifrost_ruby::graph::extractor::{
    ruby_enclosing_receiver, ruby_field_reference_owner_and_scope, ruby_receiver_type,
    ruby_seed_assignment, ruby_seed_parameter_shadows, ruby_type_owner,
};
use brokk_bifrost_ruby::graph::resolver::{
    ReceiverMode as RubyReceiverMode, ReceiverType as RubyReceiverType, RubySemanticIndex,
    ruby_field_target as ruby_field_target_from_code_unit,
};
use brokk_bifrost_ruby::graph::syntax::{
    is_call_method_identifier as ruby_is_call_method_identifier,
    is_declaration_constant as ruby_is_declaration_constant,
    is_declaration_identifier as ruby_is_declaration_identifier,
    is_dynamic_dispatch_method as ruby_is_dynamic_dispatch_method,
    is_plain_assignment_left_variable as ruby_is_plain_assignment_left_variable,
    method_receiver_mode as ruby_method_receiver_mode, node_text as ruby_node_text,
    symbol_or_string_value as ruby_symbol_or_string_value,
};
pub(crate) use rust::{
    AnalyzerRustDefinitionProvider, RustTypeLookupCache, resolve_rust_bounded,
    rust_expression_type_definition_candidates_cached, rust_expression_type_definition_fqn_cached,
    rust_field_definition_type_candidates_cached, rust_is_type_definition,
    rust_resolve_type_node_fqn,
};
use std::sync::{Arc, OnceLock};
use tree_sitter::{Node, Parser, Tree};

pub(crate) const NAVIGATION_TARGETS_TRUNCATED_DIAGNOSTIC: &str = "navigation_targets_truncated";
pub(crate) const PARTIAL_IMPORT_BOUNDARY_DIAGNOSTIC: &str = "partial_import_boundary";
pub(crate) const PARTIAL_IMPORT_UNRESOLVED_DIAGNOSTIC: &str = "partial_import_unresolved";
pub(crate) const IMPORT_BINDINGS_TRUNCATED_DIAGNOSTIC: &str = "import_bindings_truncated";
pub(crate) const CPP_NAVIGATION_STRUCTURE_UNAVAILABLE_DIAGNOSTIC: &str =
    "cpp_navigation_structure_unavailable";

mod call_sites;
mod cpp;
mod csharp;
mod go;
pub(crate) mod java;
pub(crate) mod js_ts;
mod kotlin;
mod php;
mod python;
mod ruby;
mod rust;
mod scala;
pub mod trace;

pub(crate) use brokk_bifrost_core::analyzer::usages::resolution_session;
pub use call_sites::call_signature_context;
pub(crate) use call_sites::{
    CallSiteSyntax, CallSyntaxKind, ExactCallReference, ExactCallReferenceGap,
    call_reference_ranges_in_tree, call_reference_requires_point_lookup,
    call_site_syntax_for_reference, exact_call_reference_for_call, is_call_reference_range_in_tree,
};
pub(crate) use cpp::{cpp_type_lookup_resolution_in_session, resolve_cpp_bounded};
pub(crate) use csharp::{
    CSharpTypeLookupResolution, csharp_type_lookup_resolution,
    csharp_type_lookup_resolution_in_session, resolve_csharp_bounded,
};
pub(crate) use go::{
    AnalyzerGoDefinitionProvider, GoDefinitionProvider, GoTypeLookupResolutionKind,
    go_type_lookup_resolution, resolve_go_bounded,
};
pub(crate) use java::{JavaTypeLookupResolution, java_type_lookup_resolution};
pub(crate) use kotlin::{
    KotlinDefinitionProvider, KotlinTypeLookupResolution, kotlin_type_lookup_resolution,
    kotlin_type_lookup_resolution_in_session, resolve_kotlin_bounded,
};
pub(crate) use php::{
    PhpDefinitionProvider, php_type_lookup_resolution_bounded, resolve_php_bounded,
};
pub(crate) use python::{
    PythonDefinitionProvider, python_type_lookup_resolution_bounded, resolve_python_bounded,
};
pub(crate) use resolution_session::{BoundedResolution, ResolutionSession};
pub(crate) use ruby::{
    RubyDefinitionProvider, resolve_ruby_bounded, ruby_type_lookup_resolution_bounded,
};
pub(crate) use scala::{
    ScalaDefinitionProvider, ScalaTypeLookupResolution, resolve_scala_bounded,
    scala_type_lookup_resolution, scala_type_lookup_resolution_in_session,
};
#[cfg(any(test, feature = "test-support"))]
pub use scala::{
    reset_scala_active_path_node_visits_for_test, scala_active_path_node_visits_for_test,
};
pub use trace::{
    ResolutionTraceResult, TraceCandidate, TraceCandidateRef, TraceCompleteness,
    resolve_definition_batch_with_trace,
};

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
    resolve_qualified_in_enclosing_scopes(analyzer, file, name, byte, accept)
}

/// The dotted-reference generalization of [`resolve_in_enclosing_scopes`]:
/// `internal::EachMatcher` inside `namespace testing` must resolve to
/// `testing::internal::EachMatcher` — the reference is multi-segment, so the
/// single-segment walk above cannot try it (tier-4 gmock shape, #1129's
/// sibling).
///
/// Both sides are now interned segments (M2). The reference is parsed once into
/// an [`crate::analyzer::fq_name::FqName`] via
/// [`crate::analyzer::symbol_lookup::parse_symbol_path_fq`] (which honors the
/// language's full separator set — `::`, `.`, `\`, `/`, `+` — and per-language
/// normalization), and the enclosing scope's own structured `fq` supplies the
/// prefix chain. Composing a candidate is a segment push, not a
/// `format!("{scope}.{reference}")`, so the M1-era reference-normalization shim
/// (`normalize_reference_to_fq_segments`) is gone: a `::`-qualified reference
/// resolving to a `.`-joined candidate falls straight out of the segment
/// rendering (#1162), with no per-call string massaging.
///
/// The scope prefix walk descends only across boundaries the native spelling
/// renders as a literal `.`, so a C++ `::`-headed namespace scope
/// (`cutlass::gemm::warp.OperandSharedStorage`) is never descended into its
/// sibling namespaces — exactly the legacy dot-only `namespace_prefixes` walk,
/// which is why issue #1163 stays pinned until M4 flips it deliberately.
///
/// Cache-loaded scope units carry an empty `fq` until persistence ships
/// segments (M3); they take the string fallback arm below, which renders the
/// reference to the same `.`-joined normalization the deleted shim produced and
/// walks the verbatim scope string. Both arms are proven identical by the
/// `issue_1162_separator_aware_enclosing_scope` suite and the dual-arm unit
/// tests. The fallback arm is deleted in M4.
pub(super) fn resolve_qualified_in_enclosing_scopes(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    reference: &str,
    byte: usize,
    accept: impl Fn(&CodeUnit) -> bool,
) -> Option<CodeUnit> {
    if reference.is_empty() {
        return None;
    }
    let language = language_for_file(file);
    let interner = crate::analyzer::fq_name::segment_interner();
    let reference_fq =
        crate::analyzer::symbol_lookup::parse_symbol_path_fq(language, reference, interner);
    if reference_fq.is_empty() {
        return None;
    }
    let range = Range {
        start_byte: byte,
        end_byte: byte + 1,
        start_line: 0,
        end_line: 0,
    };
    let scope_unit = analyzer.enclosing_code_unit(file, &range)?;

    // The enclosing scope unit always comes from FileState declarations, which
    // carry a populated structured `fq` (extracted at M1, rehydrated from
    // persisted segments at M3), so the composition is a pure segment push. The
    // M2-era empty-fq string fallback (which walked the verbatim scope string and
    // rendered the reference via `display`) is deleted; both sides are segments.
    if scope_unit.fq().is_empty() {
        return None;
    }
    resolve_qualified_name_in_shrinking_scopes_fq(
        language,
        scope_unit.fq(),
        &reference_fq,
        interner,
        || true,
        |fqn| analyzer.definitions(fqn).collect(),
        accept,
    )
}

/// Segment-composed sibling of [`resolve_qualified_name_in_shrinking_scopes`]:
/// tries `{scope} + reference` at the full enclosing scope, then at each
/// progressively shorter prefix of `scope`, composing each candidate by pushing
/// the reference's segments onto the scope prefix (no separator inference) and
/// rendering natively for the string-keyed `definitions` lookup.
///
/// A prefix boundary is a valid cut point only where the native rendering
/// places a literal `.`, which reproduces the legacy dot-only
/// `namespace_prefixes` walk exactly: a `::`-joined C++ namespace head, a `/`
/// path join, or a `$` nesting boundary is not a `.`, so the walk never
/// descends across it. `charge_hop` is polled once per attempted prefix (same
/// count as the string core), so budget-charging callers truncate identically.
pub(super) fn resolve_qualified_name_in_shrinking_scopes_fq(
    language: Language,
    scope: &crate::analyzer::fq_name::FqName,
    reference: &crate::analyzer::fq_name::FqName,
    interner: &crate::analyzer::fq_name::SegmentInterner,
    mut charge_hop: impl FnMut() -> bool,
    mut definitions_for: impl FnMut(&str) -> Vec<CodeUnit>,
    accept: impl Fn(&CodeUnit) -> bool,
) -> Option<CodeUnit> {
    let segments = scope.segments();
    for len in (1..=segments.len()).rev() {
        let is_cut = len == segments.len()
            || interner.separator_between(segments[len - 1], segments[len], language) == ".";
        if !is_cut {
            continue;
        }
        if !charge_hop() {
            break;
        }
        let mut candidate = crate::analyzer::fq_name::FqName::new();
        for &id in &segments[..len] {
            candidate.push(id);
        }
        for &id in reference.segments() {
            candidate.push(id);
        }
        let candidate_str = candidate.display_native(language, interner);
        if let Some(unit) = definitions_for(&candidate_str)
            .into_iter()
            .find(|unit| accept(unit))
        {
            return Some(unit);
        }
    }
    None
}

/// Budget-parametric core shared by the empty-fq fallback arm of
/// [`resolve_qualified_in_enclosing_scopes`]
/// and C#'s bounded fork (`resolve_csharp_in_enclosing_scopes`): try
/// `{prefix}.{reference}` at `scope`, then at each progressively shorter
/// dotted prefix of `scope` in turn (never the bare top level — see the doc
/// comment above), returning the first hit `definitions_for` reports that
/// `accept` approves.
///
/// `definitions_for` supplies the definitions source (an unbounded
/// `analyzer.definitions` call, or a session-aware/budget-charging one), and
/// `charge_hop` gates each prefix attempt (an always-`true` closure for
/// unbounded callers). Once `charge_hop` declines, the walk stops
/// immediately without formatting or looking up further prefixes — matching
/// how csharp's/java's per-hop `scope_step` budgets truncate the walk today.
pub(super) fn resolve_qualified_name_in_shrinking_scopes(
    scope: &str,
    reference: &str,
    mut charge_hop: impl FnMut() -> bool,
    mut definitions_for: impl FnMut(&str) -> Vec<CodeUnit>,
    accept: impl Fn(&CodeUnit) -> bool,
) -> Option<CodeUnit> {
    namespace_prefixes(scope)
        .take_while(|prefix| !prefix.is_empty())
        .map_while(|prefix| charge_hop().then_some(prefix))
        .find_map(|prefix| {
            let candidate = format!("{prefix}.{reference}");
            definitions_for(&candidate)
                .into_iter()
                .find(|unit| accept(unit))
        })
}

pub(crate) const SCALA_UNSUPPORTED_CALL_TARGET_SHAPE: &str = "unsupported_scala_call_target_shape";
pub(crate) const SCALA_UNSUPPORTED_RECEIVER: &str = "unsupported_scala_receiver";

#[derive(Debug, Clone)]
pub struct DefinitionLookupRequest {
    pub file: ProjectFile,
    pub line: Option<usize>,
    pub column: Option<usize>,
    pub start_byte: Option<usize>,
    pub end_byte: Option<usize>,
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
pub struct DefinitionLookupOutcome {
    pub status: DefinitionLookupStatus,
    pub reference: Option<ResolvedReferenceSite>,
    pub definitions: Vec<CodeUnit>,
    pub lexical_definition: Option<LexicalDefinition>,
    pub diagnostics: Vec<DefinitionLookupDiagnostic>,
}

impl DefinitionLookupOutcome {
    pub fn resolved_reference_target(&self) -> Option<&str> {
        self.reference
            .as_ref()
            .map(|reference| reference.text.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NavigationTarget {
    pub code_unit: CodeUnit,
    pub declaration_range: Option<Range>,
}

#[derive(Debug, Clone)]
pub struct NavigationLookupOutcome {
    pub status: DefinitionLookupStatus,
    pub(crate) reference: Option<ResolvedReferenceSite>,
    pub targets: Vec<NavigationTarget>,
    pub lexical_definition: Option<LexicalDefinition>,
    pub diagnostics: Vec<DefinitionLookupDiagnostic>,
    pub(crate) structure_unavailable: bool,
    pub(crate) unproven_link_unit: bool,
    pub(crate) truncated: bool,
}

impl NavigationLookupOutcome {
    pub fn resolved_reference_target(&self) -> Option<&str> {
        self.reference
            .as_ref()
            .map(|reference| reference.text.as_str())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CallTargetLookupOutcome {
    pub outcome: DefinitionLookupOutcome,
    pub structure_unavailable: bool,
    pub unproven_link_unit: bool,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefinitionLookupStatus {
    Resolved,
    NoDefinition,
    UnresolvableImportBoundary,
    Ambiguous,
    UnsupportedLanguage,
    InvalidLocation,
    NotFound,
}

impl DefinitionLookupStatus {
    pub fn as_str(self) -> &'static str {
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
pub struct DefinitionLookupDiagnostic {
    pub kind: String,
    pub message: String,
}

/// Forward definition evidence stopped at the deepest indexed selector member.
/// Consumers must not treat the accompanying declaration as the complete target
/// of the originally requested selector chain.
pub const PARTIAL_SELECTOR_CHAIN_DIAGNOSTIC_KIND: &str = "partial_selector_chain";

pub(crate) fn resolve_definition_batch(
    analyzer: &dyn IAnalyzer,
    requests: Vec<DefinitionLookupRequest>,
) -> Vec<DefinitionLookupOutcome> {
    let _scope = profiling::scope("get_definition::resolve_definition_batch");
    if profiling::enabled() {
        profiling::note(format!("request_count={}", requests.len()));
    }
    let mut context = DefinitionBatchContext::new(analyzer, requests.len() > 1);
    resolve_definition_requests(analyzer, &mut context, requests, None, None, true)
}

pub(crate) fn resolve_navigation_batch(
    analyzer: &dyn IAnalyzer,
    requests: Vec<DefinitionLookupRequest>,
    operation: NavigationOperation,
    cancellation: Option<&CancellationToken>,
    allow_rust_field_receiver_lexical: bool,
) -> Vec<NavigationLookupOutcome> {
    let _scope = profiling::scope("get_definition::resolve_navigation_batch");
    if profiling::enabled() {
        profiling::note(format!(
            "request_count={}, operation={operation:?}",
            requests.len()
        ));
    }
    let mut context = DefinitionBatchContext::new(analyzer, requests.len() > 1);
    resolve_navigation_requests(
        analyzer,
        &mut context,
        requests,
        operation,
        cancellation,
        allow_rust_field_receiver_lexical,
    )
}

fn resolve_navigation_requests<'a>(
    analyzer: &'a dyn IAnalyzer,
    context: &mut DefinitionBatchContext<'a>,
    requests: Vec<DefinitionLookupRequest>,
    operation: NavigationOperation,
    cancellation: Option<&CancellationToken>,
    allow_rust_field_receiver_lexical: bool,
) -> Vec<NavigationLookupOutcome> {
    const MAX_NAVIGATION_TARGETS_PER_RESULT: usize = 256;
    const MAX_NAVIGATION_TARGETS_PER_BATCH: usize = 1024;
    context.navigation_target_limit = (MAX_NAVIGATION_TARGETS_PER_BATCH / requests.len().max(1))
        .clamp(1, MAX_NAVIGATION_TARGETS_PER_RESULT);
    let languages: Vec<_> = requests
        .iter()
        .map(|request| language_for_file(&request.file))
        .collect();
    let outcomes = resolve_definition_requests(
        analyzer,
        context,
        requests,
        cancellation,
        Some(operation),
        allow_rust_field_receiver_lexical,
    );
    languages
        .into_iter()
        .zip(outcomes)
        .map(|(language, outcome)| {
            navigation_lookup_outcome(analyzer, context, outcome, language, operation)
        })
        .collect()
}

/// Resolve one batch of requests, optionally draining the resolution trace
/// after each one.
///
/// `trace_session` and `traces` travel together and are `None`/empty for every
/// caller but [`trace::resolve_definition_batch_with_trace`]. They are
/// parameters rather than context state because the drain must happen exactly
/// at the per-request boundary, which is here and nowhere else: the recorder is
/// append-only, so without a drain point every request would inherit the rows
/// of the ones before it.
fn resolve_definition_requests<'a>(
    analyzer: &'a dyn IAnalyzer,
    context: &mut DefinitionBatchContext<'a>,
    requests: Vec<DefinitionLookupRequest>,
    cancellation: Option<&CancellationToken>,
    operation: Option<NavigationOperation>,
    allow_rust_field_receiver_lexical: bool,
) -> Vec<DefinitionLookupOutcome> {
    resolve_definition_requests_traced(
        analyzer,
        context,
        requests,
        cancellation,
        operation,
        allow_rust_field_receiver_lexical,
        None,
        &mut Vec::new(),
    )
}

#[allow(clippy::too_many_arguments)]
fn resolve_definition_requests_traced<'a>(
    analyzer: &'a dyn IAnalyzer,
    context: &mut DefinitionBatchContext<'a>,
    requests: Vec<DefinitionLookupRequest>,
    cancellation: Option<&CancellationToken>,
    operation: Option<NavigationOperation>,
    allow_rust_field_receiver_lexical: bool,
    trace_session: Option<&trace::TraceSession>,
    traces: &mut Vec<Vec<TraceCandidate>>,
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
            let outcome = resolve_one(
                analyzer,
                context,
                request,
                operation,
                cancellation,
                allow_rust_field_receiver_lexical,
            );
            if is_python && let Some(remaining) = remaining_python_requests.get_mut(&file) {
                *remaining -= 1;
                if *remaining == 0 {
                    context.python_contexts.remove(&file);
                }
            }
            if let Some(session) = trace_session {
                traces.push(session.take_request());
            }
            outcome
        })
        .collect()
}

pub fn resolve_definition_batch_with_source(
    analyzer: &dyn IAnalyzer,
    requests: Vec<DefinitionLookupRequest>,
    file: ProjectFile,
    source: Arc<str>,
) -> Vec<DefinitionLookupOutcome> {
    let mut context = DefinitionBatchContext::new(analyzer, requests.len() > 1);
    context.sources.insert(file, Ok(source));
    resolve_definition_requests(analyzer, &mut context, requests, None, None, true)
}

pub fn resolve_navigation_batch_with_source(
    analyzer: &dyn IAnalyzer,
    requests: Vec<DefinitionLookupRequest>,
    file: ProjectFile,
    source: Arc<str>,
    operation: NavigationOperation,
) -> Vec<NavigationLookupOutcome> {
    let mut context = DefinitionBatchContext::new(analyzer, requests.len() > 1);
    context.sources.insert(file, Ok(source));
    resolve_navigation_requests(analyzer, &mut context, requests, operation, None, true)
}

pub fn navigation_declaration_site_targets(
    analyzer: &dyn IAnalyzer,
    candidate: CodeUnit,
    operation: NavigationOperation,
) -> Vec<NavigationTarget> {
    if language_for_file(candidate.source()) != Language::Cpp {
        return vec![NavigationTarget {
            code_unit: candidate,
            declaration_range: None,
        }];
    }
    let mut context = DefinitionBatchContext::new(analyzer, false);
    cpp::select_navigation_targets(&mut context, &[candidate], operation).targets
}

pub fn navigation_declaration_site_at_offset(
    file: &ProjectFile,
    source: &str,
    offset: usize,
) -> Option<CodeUnit> {
    (language_for_file(file) == Language::Cpp)
        .then(|| cpp::declaration_at_offset(file, source, offset))
        .flatten()
}

pub fn resolve_definition_batch_with_source_and_cancellation(
    analyzer: &dyn IAnalyzer,
    requests: Vec<DefinitionLookupRequest>,
    file: ProjectFile,
    source: Arc<str>,
    cancellation: &CancellationToken,
) -> Vec<DefinitionLookupOutcome> {
    let mut context = DefinitionBatchContext::new(analyzer, requests.len() > 1);
    context.sources.insert(file, Ok(source));
    resolve_definition_requests(
        analyzer,
        &mut context,
        requests,
        Some(cancellation),
        None,
        true,
    )
}

pub(crate) fn resolve_call_target_batch_with_source(
    analyzer: &dyn IAnalyzer,
    requests: Vec<DefinitionLookupRequest>,
    file: ProjectFile,
    source: Arc<str>,
    cancellation: Option<&CancellationToken>,
) -> Vec<CallTargetLookupOutcome> {
    if language_for_file(&file) != Language::Cpp {
        let outcomes = match cancellation {
            Some(cancellation) => resolve_definition_batch_with_source_and_cancellation(
                analyzer,
                requests,
                file,
                source,
                cancellation,
            ),
            None => resolve_definition_batch_with_source(analyzer, requests, file, source),
        };
        return outcomes
            .into_iter()
            .map(|outcome| CallTargetLookupOutcome {
                outcome,
                structure_unavailable: false,
                unproven_link_unit: false,
                truncated: false,
            })
            .collect();
    }

    let mut context = DefinitionBatchContext::new(analyzer, requests.len() > 1);
    context.sources.insert(file, Ok(source));
    resolve_navigation_requests(
        analyzer,
        &mut context,
        requests,
        NavigationOperation::Definition,
        cancellation,
        true,
    )
    .into_iter()
    .map(|outcome| CallTargetLookupOutcome {
        structure_unavailable: outcome.structure_unavailable,
        unproven_link_unit: outcome.unproven_link_unit,
        truncated: outcome.truncated,
        outcome: DefinitionLookupOutcome {
            status: outcome.status,
            reference: outcome.reference,
            definitions: outcome
                .targets
                .into_iter()
                .map(|target| target.code_unit)
                .collect(),
            lexical_definition: outcome.lexical_definition,
            diagnostics: outcome.diagnostics,
        },
    })
    .collect()
}

pub fn resolve_call_reference_definition_with_source(
    analyzer: &dyn IAnalyzer,
    request: DefinitionLookupRequest,
    file: ProjectFile,
    source: Arc<str>,
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

    Some(resolve_one(
        analyzer,
        &mut context,
        request,
        None,
        None,
        true,
    ))
}

#[derive(Clone)]
pub(super) struct JsTsDefinitionContext {
    pub(super) imports: JsTsImportBinder,
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
    pub(super) file: ProjectFile,
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
    scala_package_contexts: HashMap<ProjectFile, ScalaPackageContextIndex>,
    scala_lookup_cache: scala::ScalaLookupCache,
    sources: HashMap<ProjectFile, Result<Arc<str>, String>>,
    trees: HashMap<(ProjectFile, Language), Option<Tree>>,
    line_starts: HashMap<ProjectFile, Arc<Vec<usize>>>,
    cpp_visibility: HashMap<ProjectFile, Arc<CppVisibilityIndex<'a>>>,
    // Candidate declaration ranges belong to the analyzer generation, so these
    // caches must use indexed source rather than the request's live disk source.
    cpp_indexed_sources: HashMap<ProjectFile, Option<Arc<String>>>,
    cpp_indexed_trees: HashMap<ProjectFile, Option<Tree>>,
    cpp_navigation_indexes: HashMap<ProjectFile, Option<Arc<cpp::CppNavigationIndex>>>,
    cpp_structural_alias_paths: HashMap<CodeUnit, Vec<String>>,
    cpp_class_ranges: HashMap<ProjectFile, Arc<ClassRangeIndex>>,
    enclosing_owner_chains: HashMap<CodeUnit, Arc<Vec<CodeUnit>>>,
    python_contexts: HashMap<ProjectFile, Arc<python::PythonDefinitionContext>>,
    navigation_target_limit: usize,
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
            scala_package_contexts: HashMap::default(),
            scala_lookup_cache: scala::ScalaLookupCache::default(),
            sources: HashMap::default(),
            trees: HashMap::default(),
            line_starts: HashMap::default(),
            cpp_visibility: HashMap::default(),
            cpp_indexed_sources: HashMap::default(),
            cpp_indexed_trees: HashMap::default(),
            cpp_navigation_indexes: HashMap::default(),
            cpp_structural_alias_paths: HashMap::default(),
            cpp_class_ranges: HashMap::default(),
            enclosing_owner_chains: HashMap::default(),
            python_contexts: HashMap::default(),
            navigation_target_limit: 256,
            #[cfg(test)]
            cpp_class_range_builds: 0,
            #[cfg(test)]
            python_build_counters: Arc::default(),
        }
    }

    fn bounded_support(&self) -> &dyn BoundedDefinitionLookup {
        &self.bounded_support
    }

    fn source(&mut self, file: &ProjectFile) -> Result<Arc<str>, String> {
        self.sources
            .entry(file.clone())
            .or_insert_with(|| {
                file.read_to_string()
                    .map(Arc::<str>::from)
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
            let definitions =
                go::AnalyzerGoDefinitionProvider::new(go, self.analyzer.semantic_model_overlay());
            let (aliases, dot_imports) =
                go::go_definition_import_namespaces(&definitions, go, file);
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
                file: file.clone(),
                package: Arc::from(scala_package_name_of(scala, file).unwrap_or_default()),
                imports: Arc::new(scala.import_info_of(file)),
            })
            .clone()
    }

    fn scala_package_prefixes(
        &mut self,
        file: &ProjectFile,
        root: Node<'_>,
        source: &str,
        byte: usize,
    ) -> Vec<String> {
        self.scala_package_contexts
            .entry(file.clone())
            .or_insert_with(|| ScalaPackageContextIndex::new(root, source))
            .prefixes_at(byte)
            .to_vec()
    }

    fn cpp_visibility(
        &mut self,
        cpp: &'a crate::analyzer::CppAnalyzer,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
    ) -> Arc<CppVisibilityIndex<'a>> {
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

    #[cfg(test)]
    fn scala_lookup_cache_counts(&self) -> (usize, usize) {
        (
            self.scala_lookup_cache.direct_children_builds_for_test(),
            self.scala_lookup_cache.direct_ancestor_builds_for_test(),
        )
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

    fn cpp_navigation_index(&mut self, file: &ProjectFile) -> Option<Arc<cpp::CppNavigationIndex>> {
        if let Some(index) = self.cpp_navigation_indexes.get(file) {
            return index.clone();
        }
        let index = self.cpp_indexed_source(file).and_then(|source| {
            let tree = self.cpp_indexed_tree(file)?;
            Some(Arc::new(cpp::CppNavigationIndex::build(
                file, &source, &tree,
            )))
        });
        self.cpp_navigation_indexes
            .insert(file.clone(), index.clone());
        index
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

    /// Generalized, memoized version of the enclosing-owner-chain walk (see
    /// `common::enclosing_owner_chain`): `owner` plus every contiguous
    /// ancestor `accept` approves, stopping at the first rejection.
    ///
    /// The cache key is `owner` alone, not `(owner, accept)` — every caller
    /// today shares one predicate (C++'s `CodeUnit::is_class`). A second
    /// predicate reused through this same cache would silently return the
    /// first-cached chain for a given owner; give it a predicate-aware key
    /// before adding one.
    fn enclosing_owner_chain(
        &mut self,
        owner: CodeUnit,
        accept: impl Fn(&CodeUnit) -> bool,
    ) -> Arc<Vec<CodeUnit>> {
        let analyzer = self.analyzer;
        self.enclosing_owner_chains
            .entry(owner.clone())
            .or_insert_with(|| {
                Arc::new(
                    crate::analyzer::usages::common::enclosing_owner_chain(owner, |unit| {
                        analyzer.parent_of(unit)
                    })
                    .take_while(|unit| accept(unit))
                    .collect(),
                )
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

fn resolve_one<'a>(
    analyzer: &'a dyn IAnalyzer,
    context: &mut DefinitionBatchContext<'a>,
    request: DefinitionLookupRequest,
    operation: Option<NavigationOperation>,
    cancellation: Option<&CancellationToken>,
    allow_rust_field_receiver_lexical: bool,
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
    let site = if language == Language::Ruby {
        tree.as_ref()
            .map(|tree| ruby::ruby_site_for_focus(site.clone(), tree, &source))
            .unwrap_or(site)
    } else {
        site
    };
    if let Some(tree) = tree.as_ref()
        && !(!allow_rust_field_receiver_lexical
            && language == Language::Rust
            && rust::focused_site_is_field_receiver(tree.root_node(), &site))
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
            Some(
                LexicalBindingResolution::Parameter(definition)
                | LexicalBindingResolution::OtherLocal(definition),
            ) => {
                return finish_lookup_outcome(lexical_definition_outcome(definition), site);
            }
            None => {}
        }
    }
    let _dispatch_scope = profiling::scope("get_definition::language_dispatch");
    let resolved = match language {
        Language::Rust => {
            if let Some(cancellation) = cancellation {
                match rust::resolve_rust_cancellable(
                    analyzer,
                    &request.file,
                    &source,
                    tree.as_ref(),
                    &site,
                    &mut context.rust_type_cache,
                    operation,
                    ReceiverAnalysisBudget::default(),
                    cancellation,
                ) {
                    resolution_session::BoundedResolution::Complete { value, .. } => value,
                    resolution_session::BoundedResolution::Exceeded { limit, .. } => no_definition(
                        "resolution_budget_exceeded",
                        format!(
                            "Rust definition resolution exceeded its {} budget",
                            limit.as_str()
                        ),
                    ),
                    resolution_session::BoundedResolution::Cancelled { .. } => {
                        no_definition("cancelled", "Rust definition resolution was cancelled")
                    }
                }
            } else {
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
                            operation,
                        )
                    },
                )
            }
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
            let selector = tree
                .as_ref()
                .and_then(|tree| go_selector_descriptor(tree.root_node(), &site));
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
                    selector.as_ref(),
                ))
            });
            if let Some(go_analyzer) = go {
                go::resolve_go(
                    analyzer,
                    &go::AnalyzerGoDefinitionProvider::new(
                        go_analyzer,
                        analyzer.semantic_model_overlay(),
                    ),
                    &request.file,
                    &source,
                    tree.as_ref(),
                    &site,
                    selector.as_ref(),
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
        Language::Kotlin => kotlin::resolve_kotlin(
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

    let resolved = if let Some(operation) = operation {
        if language == Language::Cpp {
            resolved
        } else {
            finalize_navigation_outcome(resolved, operation)
        }
    } else {
        resolved
    };

    finish_lookup_outcome(resolved, site)
}

fn finish_lookup_outcome(
    mut outcome: DefinitionLookupOutcome,
    site: ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    if outcome.reference.is_none() {
        outcome.reference = Some(site);
    }
    outcome
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

/// Parse `source` under the grammar registered for `language`.
///
/// `file` selects the grammar flavor, which only TypeScript distinguishes (`.tsx`); every
/// other language answers one grammar for both. `None` means the language has no grammar
/// (`Language::None`) or the source did not parse.
pub fn parse_tree_for_language(
    file: &ProjectFile,
    language: Language,
    source: &str,
) -> Option<Tree> {
    let grammar = crate::analyzer::parser_language_for_path(language, file.rel_path())?;
    let mut parser = Parser::new();
    parser.set_language(&grammar).ok()?;
    parser.parse(source, None)
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
    let outcome = DefinitionLookupOutcome {
        status,
        reference: None,
        definitions: candidates,
        lexical_definition: None,
        diagnostics,
    };
    trace::record_selected_units(&outcome);
    outcome
}

fn finalize_navigation_outcome(
    mut outcome: DefinitionLookupOutcome,
    operation: NavigationOperation,
) -> DefinitionLookupOutcome {
    sort_units(&mut outcome.definitions);
    outcome.definitions.dedup();
    if outcome.lexical_definition.is_some() {
        outcome.status = DefinitionLookupStatus::Resolved;
        return outcome;
    }
    if outcome.definitions.is_empty() {
        return outcome;
    }
    outcome.status = if outcome.definitions.len() == 1 {
        DefinitionLookupStatus::Resolved
    } else {
        DefinitionLookupStatus::Ambiguous
    };
    outcome
        .diagnostics
        .retain(|diagnostic| diagnostic.kind != "ambiguous_definition");
    if outcome.status == DefinitionLookupStatus::Ambiguous {
        outcome.diagnostics.push(DefinitionLookupDiagnostic {
            kind: "ambiguous_definition".to_string(),
            message: format!(
                "{} navigation resolved to multiple workspace targets",
                match operation {
                    NavigationOperation::Declaration => "declaration",
                    NavigationOperation::Definition => "definition",
                }
            ),
        });
    }
    outcome
}

fn navigation_lookup_outcome(
    _analyzer: &dyn IAnalyzer,
    context: &mut DefinitionBatchContext<'_>,
    outcome: DefinitionLookupOutcome,
    language: Language,
    operation: NavigationOperation,
) -> NavigationLookupOutcome {
    let DefinitionLookupOutcome {
        mut status,
        reference,
        definitions,
        lexical_definition,
        mut diagnostics,
    } = outcome;
    let (mut targets, structure_unavailable, unproven_link_unit, mut truncated) =
        if language == Language::Cpp {
            let selection = cpp::select_navigation_targets(context, &definitions, operation);
            (
                selection.targets,
                selection.structure_unavailable,
                selection.unproven_link_unit,
                selection.truncated,
            )
        } else {
            let mut targets: Vec<_> = definitions
                .iter()
                .cloned()
                .map(|code_unit| NavigationTarget {
                    code_unit,
                    declaration_range: None,
                })
                .collect();
            let truncated = targets.len() > context.navigation_target_limit;
            targets.truncate(context.navigation_target_limit);
            (targets, false, false, truncated)
        };
    targets.sort_by(|left, right| {
        (&left.code_unit, left.declaration_range).cmp(&(&right.code_unit, right.declaration_range))
    });
    targets.dedup();

    diagnostics.retain(|diagnostic| {
        !matches!(
            diagnostic.kind.as_str(),
            "no_definition"
                | "no_declaration"
                | NAVIGATION_TARGETS_TRUNCATED_DIAGNOSTIC
                | cpp::CPP_UNPROVEN_LINK_UNIT_DIAGNOSTIC
                | CPP_NAVIGATION_STRUCTURE_UNAVAILABLE_DIAGNOSTIC
        )
    });

    if lexical_definition.is_some() {
        status = DefinitionLookupStatus::Resolved;
        truncated = false;
    } else if targets.is_empty() {
        if !definitions.is_empty() {
            diagnostics.retain(|diagnostic| diagnostic.kind != "ambiguous_definition");
            status = DefinitionLookupStatus::NoDefinition;
            diagnostics.push(DefinitionLookupDiagnostic {
                kind: match operation {
                    NavigationOperation::Declaration => "no_declaration",
                    NavigationOperation::Definition => "no_definition",
                }
                .to_string(),
                message: match operation {
                    NavigationOperation::Declaration => {
                        "navigation candidates contain no declaration target"
                    }
                    NavigationOperation::Definition => {
                        "navigation candidates contain no implementation body"
                    }
                }
                .to_string(),
            });
        }
    } else {
        diagnostics.retain(|diagnostic| diagnostic.kind != "ambiguous_definition");
        status = if targets.len() == 1 && !truncated {
            DefinitionLookupStatus::Resolved
        } else {
            DefinitionLookupStatus::Ambiguous
        };
        if status == DefinitionLookupStatus::Ambiguous {
            diagnostics.push(DefinitionLookupDiagnostic {
                kind: "ambiguous_definition".to_string(),
                message: format!(
                    "{} navigation resolved to multiple workspace targets",
                    match operation {
                        NavigationOperation::Declaration => "declaration",
                        NavigationOperation::Definition => "definition",
                    }
                ),
            });
        }
    }

    if structure_unavailable {
        diagnostics.push(DefinitionLookupDiagnostic {
            kind: CPP_NAVIGATION_STRUCTURE_UNAVAILABLE_DIAGNOSTIC.to_string(),
            message: "one or more C/C++ candidates could not be classified from indexed syntax"
                .to_string(),
        });
    }
    if unproven_link_unit {
        diagnostics.push(DefinitionLookupDiagnostic {
            kind: cpp::CPP_UNPROVEN_LINK_UNIT_DIAGNOSTIC.to_string(),
            message:
                "multiple C/C++ definition bodies remain, but no build graph proves one link unit"
                    .to_string(),
        });
    }
    if truncated {
        diagnostics.push(DefinitionLookupDiagnostic {
            kind: NAVIGATION_TARGETS_TRUNCATED_DIAGNOSTIC.to_string(),
            message: format!(
                "{} navigation targets were truncated to the request budget of {}",
                match operation {
                    NavigationOperation::Declaration => "declaration",
                    NavigationOperation::Definition => "definition",
                },
                context.navigation_target_limit
            ),
        });
    }

    NavigationLookupOutcome {
        status,
        reference,
        targets,
        lexical_definition,
        diagnostics,
        structure_unavailable,
        unproven_link_unit,
        truncated,
    }
}

fn ambiguous_candidates_outcome(
    mut candidates: Vec<CodeUnit>,
    message: impl Into<String>,
) -> DefinitionLookupOutcome {
    sort_units(&mut candidates);
    candidates.dedup();
    DefinitionLookupOutcome {
        status: DefinitionLookupStatus::Ambiguous,
        reference: None,
        definitions: candidates,
        lexical_definition: None,
        diagnostics: vec![DefinitionLookupDiagnostic {
            kind: "ambiguous_definition".to_string(),
            message: message.into(),
        }],
    }
}

fn lexical_definition_outcome(definition: LexicalDefinition) -> DefinitionLookupOutcome {
    let outcome = DefinitionLookupOutcome {
        status: DefinitionLookupStatus::Resolved,
        reference: None,
        definitions: Vec::new(),
        lexical_definition: Some(definition),
        diagnostics: Vec::new(),
    };
    trace::record_selected_lexical(&outcome);
    outcome
}

fn definition_symbol_key(unit: &CodeUnit) -> (String, String) {
    (unit.fq_name(), format!("{:?}", unit.kind()))
}

/// Emit a confident cross-workspace boundary claim *without* the structural
/// workspace-internal gate. This is the raw emitter; it is `_unchecked` on
/// purpose so that every remaining call site is greppable and must justify why
/// it does not go through [`gated_boundary`].
///
/// Prefer [`gated_boundary`] for any new site: it forces the second, load-
/// bearing question ("does the workspace nonetheless declare this?") to be
/// answered structurally. Only call `boundary_unchecked` when that question is
/// already answered upstream on this path — an exhausted resolver verdict, a
/// preceding enclosing-scope/workspace-namespace probe that returned early, or a
/// predicate that already fused the workspace check. Each such call MUST carry a
/// `// gated upstream:` comment naming where its guard lives.
fn boundary_unchecked(message: String) -> DefinitionLookupOutcome {
    diagnostic_outcome(
        DefinitionLookupStatus::UnresolvableImportBoundary,
        "unresolvable_import_boundary",
        import_boundary_workspace_message(message),
    )
}

/// Emit a confident cross-workspace boundary claim only when the target is *not*
/// workspace-internal.
///
/// Every confident `boundary()` claim answers two questions, and the second one
/// is the one call sites keep forgetting:
///
/// 1. Is there an *external signal* — an unresolved import/include/using, a
///    looks-external path? The caller checks this at the call site (it is
///    language- and shape-specific) and only reaches here when it is true.
/// 2. Does the workspace nonetheless *declare or contain* this target — a
///    same-named enclosing-scope member (the #1126 shape) or a workspace
///    namespace/module the qualifier names (the #1089 shape)? If so, the honest
///    outcome is `no_definition`, never a boundary.
///
/// `workspace_internal` answers (2). Routing confident claims through this
/// constructor makes the second check structural instead of a per-site
/// convention: a new emission site cannot skip it, because it cannot reach
/// [`boundary_unchecked`] without supplying the closure. Where both guard
/// families apply, callers `OR` them inside the closure.
fn gated_boundary(
    workspace_internal: impl FnOnce() -> bool,
    boundary_message: String,
    no_definition_kind: impl Into<String>,
    no_definition_message: impl Into<String>,
) -> DefinitionLookupOutcome {
    if workspace_internal() {
        no_definition(no_definition_kind, no_definition_message)
    } else {
        trace::record_boundary_gate();
        boundary_unchecked(boundary_message)
    }
}

/// Workspace declarations sitting at *exactly* `fqn` but written in a language
/// other than `own_language`.
///
/// Polyglot repositories address one declaration from two languages that share a
/// fully-qualified namespace: Scala names Java types by their exact JVM fq, and
/// pythonnet's Python tests name CLR types by their exact CLR fq
/// (`Python.Test.ClassCtorTest2`).  A language-scoped resolver sees none of
/// those declarations, so without this it cannot tell "not in the workspace"
/// apart from "in the workspace, in another language" — and the confident
/// boundary claim fires for a workspace-indexed target (#1174, same invariant as
/// #1126/#1089).
///
/// Matching is exact-fq only, never normalized and never identifier-level, so a
/// merely same-named declaration in another language can never be produced.
fn cross_language_declarations(
    support: &dyn BoundedDefinitionLookup,
    fqn: &str,
    own_language: Language,
) -> Vec<CodeUnit> {
    let mut units = support
        .fqn_in_any_language(fqn)
        .into_iter()
        .filter(|unit| unit.fq_name() == fqn && language_for_file(unit.source()) != own_language)
        .collect::<Vec<_>>();
    sort_units(&mut units);
    units.dedup();
    units
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
        analyzer
            .test_hooks()
            .reset_global_usage_definition_index_build_count_for_test();
        analyzer
            .test_hooks()
            .reset_full_declaration_scan_count_for_test();
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

        let outcomes =
            resolve_definition_requests(analyzer, &mut context, requests, None, None, false);

        assert!(outcomes.iter().all(|outcome| {
            outcome.status == DefinitionLookupStatus::Resolved
                && outcome.definitions[0]
                    .fq_name()
                    .starts_with("service.Service.")
        }));
        assert_eq!(context.python_build_counts(), (1, 1, 1, 0));
        assert_eq!(
            analyzer
                .test_hooks()
                .global_usage_definition_index_build_count_for_test(),
            0
        );
        assert_eq!(
            analyzer.test_hooks().full_declaration_scan_count_for_test(),
            0
        );
        assert!(context.python_contexts.is_empty());
    }

    #[test]
    fn rust_batch_context_reuses_supplied_syntax_for_repeated_field_lookups() {
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

        let outcomes =
            resolve_definition_requests(analyzer, &mut context, requests, None, None, false);

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
            0,
            "same-file definition lookup should reuse the batch's supplied syntax without reparsing"
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
        assert_eq!(first.imports, second.imports);
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
        let tree =
            parse_tree_for_language(&file, Language::Scala, source).expect("parse Scala source");
        let mut context = DefinitionBatchContext::new(analyzer, true);

        let first = context.scala_context(scala, &file);
        let second = context.scala_context(scala, &file);
        let first_prefixes =
            context.scala_package_prefixes(&file, tree.root_node(), source, source.len());
        let second_prefixes = context.scala_package_prefixes(&file, tree.root_node(), source, 0);

        assert_eq!(context.scala_contexts.len(), 1);
        assert_eq!(context.scala_package_contexts.len(), 1);
        assert_eq!(first.package.as_ref(), "demo");
        assert_eq!(first.imports, second.imports);
        assert_eq!(first_prefixes, ["demo"]);
        assert_eq!(second_prefixes, ["demo"]);
    }

    #[test]
    fn scala_batch_context_reuses_direct_children_for_named_arguments() {
        let source = "package demo\nobject Main {\n  class Widget(val alpha: Boolean, val beta: Boolean)\n  val widget = new Widget(alpha = true, beta = false)\n}\n";
        let fixture = AnalyzerFixture::new_for_language(Language::Scala, &[("main.scala", source)]);
        let file = ProjectFile::new(fixture.project_root(), "main.scala");
        let analyzer = fixture.analyzer.analyzer();
        let mut context = DefinitionBatchContext::new(analyzer, true);
        let requests = ["alpha", "beta"]
            .into_iter()
            .map(|needle| {
                let start_byte = source.rfind(needle).expect("named argument in source");
                DefinitionLookupRequest {
                    file: file.clone(),
                    line: None,
                    column: None,
                    start_byte: Some(start_byte),
                    end_byte: Some(start_byte + needle.len()),
                }
            })
            .collect::<Vec<_>>();

        let _outcomes =
            resolve_definition_requests(analyzer, &mut context, requests, None, None, true);
        assert_eq!(context.scala_lookup_cache_counts(), (1, 0));
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
            None,
            false,
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

        let outcomes =
            resolve_definition_requests(analyzer, &mut context, requests, None, None, false);

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

        let outcomes =
            resolve_definition_requests(analyzer, &mut context, requests, None, None, false);

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

        let outcomes =
            resolve_definition_requests(analyzer, &mut context, requests, None, None, false);

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

        let outcomes =
            resolve_definition_requests(&analyzer, &mut context, requests, None, None, false);

        assert_eq!(outcomes.len(), REFERENCE_COUNT);
        assert!(outcomes.iter().all(|outcome| {
            outcome.status == DefinitionLookupStatus::NoDefinition && outcome.definitions.is_empty()
        }));
        assert_eq!(
            context.cpp_class_range_builds, 1,
            "focused qualifiers in one file should share one class-range index"
        );
        assert_eq!(
            context.enclosing_owner_chains.len(),
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
            Arc::from(source),
        );
        let first_batch_validations = analyzer.live_oid_validation_count_for_test(&types);
        let second = resolve_definition_batch_with_source(
            &analyzer,
            vec![requests[0].clone()],
            consumer,
            Arc::from(source),
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
            Arc::from(source),
        );
        let first_batch_classifications = analyzer.type_alias_classification_count_for_test();
        let second = resolve_definition_batch_with_source(
            &analyzer,
            vec![requests[1].clone()],
            consumer,
            Arc::from(source),
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
