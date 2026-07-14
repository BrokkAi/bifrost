mod capabilities;
mod clone_detection;
pub mod cognitive_complexity;
#[cfg(test)]
mod cognitive_complexity_tests;
pub(crate) mod common;
mod config;
mod cpp;
mod csharp;
pub(crate) mod declaration_range;
mod global_usage_definition_index;
mod go;
mod i_analyzer;
mod java;
mod javascript;
mod js_ts;
pub(crate) mod lexical_definitions;
mod model;
mod multi_analyzer;
mod php;
mod pool_memo;
mod project;
mod python;
pub(crate) mod reference_candidates;
mod ruby;
mod rust;
mod scala;
pub(crate) mod semantic_diagnostics;
mod source_content;
pub mod store;
pub mod structural;
pub(crate) mod symbol_lookup;
pub(crate) mod test_paths;
pub(crate) mod tree_sitter_analyzer;
pub(crate) mod type_relations;
mod typescript;
mod usage_facts;
pub mod usages;
mod workspace;

pub use capabilities::{
    CapabilityProvider, ImportAnalysisProvider, TestDetectionProvider, TypeAliasProvider,
    TypeHierarchyProvider,
};
pub(crate) use capabilities::{
    build_direct_descendant_index, build_reverse_file_index, build_reverse_import_index,
    memoized_reverse_file_index, memoized_reverse_import_index, resolve_imported_files_from_infos,
};
pub use config::{
    AnalyzerConfig, JavaAnalyzerConfig, JavaExternalArtifact, JavaExternalDependencies,
    JavaMavenCoordinate,
};
pub use cpp::CppAnalyzer;
pub(crate) use cpp::{
    IncludeTargetIndex, include_paths as cpp_include_paths, node_text as cpp_node_text,
    normalize_cpp_whitespace, resolve_include_targets, resolve_include_targets_with_index,
};
pub use csharp::CSharpAnalyzer;
pub(crate) use csharp::{
    CSharpMemberName, csharp_as_expression_type_operand, csharp_attribute_name_node,
    csharp_attribute_terminal_name, csharp_attribute_type_names, csharp_callable_arity,
    csharp_conditional_member_access, csharp_member_name, csharp_method_generic_arity,
    csharp_normalize_full_name, csharp_signature_return_type, csharp_source_identifier,
    csharp_source_name_segment, csharp_type_node_identity, csharp_unqualified_invocation_for_name,
    csharp_using_directive_is_global, csharp_using_directive_is_static,
    csharp_using_directive_namespace, csharp_using_directive_target,
};
pub use global_usage_definition_index::GlobalUsageDefinitionIndex;
pub(crate) use global_usage_definition_index::{
    AnalyzerDefinitionLookup, BoundedDefinitionLookup, ForwardQueryProvider,
    impl_forward_query_provider,
};
pub use go::GoAnalyzer;
pub(crate) use go::{
    GO_MODULE_SCOPE_SEGMENT,
    packages::{GoModuleRoot, go_module_roots},
};
pub(crate) use i_analyzer::AnalyzerQueryScope;
pub use i_analyzer::IAnalyzer;
pub use java::JavaAnalyzer;
pub use javascript::JavascriptAnalyzer;
pub(crate) use js_ts::{AliasResolver, resolve_js_ts_module_specifier};
pub(crate) use model::SemanticDiagnostic;
pub use model::{
    CallableArity, CloneSmell, CloneSmellWeights, CodeBaseMetrics, CodeUnit, CodeUnitType,
    CommentDensityStats, DeclarationInfo, DeclarationKind, ExceptionHandlingSmell,
    ExceptionSmellWeights, ImportInfo, Language, MaintainabilitySizeSmell,
    MaintainabilitySizeSmellWeights, ParameterMetadata, ParseError, ParseErrorKind, ProjectFile,
    Range, RubyMethodDispatchMode, SearchSymbolCandidate, SignatureMetadata, SummaryFileProjection,
    TestAssertionSmell, TestAssertionWeights, metrics_from_declarations,
};
pub(crate) use multi_analyzer::resolve_analyzer;
pub use multi_analyzer::{AnalyzerDelegate, MultiAnalyzer};
pub use php::{
    PhpAnalyzer, PhpUseAliases, parse_php_use_aliases, parse_php_use_aliases_by_kind,
    parse_php_use_aliases_from_source, php_namespace_to_fq,
};
pub(crate) use php::{
    PhpFileContext, php_signature_return_type_text, resolve_php_constant, resolve_php_function,
    resolve_php_type,
};
pub(crate) use pool_memo::PoolSafeMemo;
pub use project::{
    DEFAULT_MAX_OVERLAY_BYTES, FileSetProject, FilesystemProject, MultiRootProject, OverlayProject,
    Project, TestProject, collect_workspace_files,
};
pub use python::PythonAnalyzer;
pub use ruby::RubyAnalyzer;
pub(crate) use ruby::RubySemanticFacts;
pub(crate) use rust::rust_is_field_declaration_name;
pub use rust::{RustAnalyzer, RustReferenceContext};
pub use scala::ScalaAnalyzer;
pub(crate) use scala::scala_parenthesized_arity;
pub use source_content::SourceContent;
pub(crate) use tree_sitter_analyzer::{
    AnalyzerStoreContext, BulkFileStateSource, default_store_context, persistent_store_context,
};
pub use tree_sitter_analyzer::{
    BuildProgress, BuildProgressEvent, BuildProgressPhase, LanguageAdapter, TreeSitterAnalyzer,
};
pub use typescript::TypescriptAnalyzer;
pub(crate) use usage_facts::UsageFactsIndex;
pub use workspace::{EmptyAnalyzer, WorkspaceAnalyzer};

/// Resolve the default parser grammar registered for a language.
pub(crate) fn parser_language_for(language: Language) -> Option<tree_sitter::Language> {
    Some(match language {
        Language::Java => tree_sitter_java::LANGUAGE.into(),
        Language::Go => tree_sitter_go::LANGUAGE.into(),
        Language::Cpp => tree_sitter_cpp::LANGUAGE.into(),
        Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        Language::Python => tree_sitter_python::LANGUAGE.into(),
        Language::Rust => tree_sitter_rust::LANGUAGE.into(),
        Language::Php => tree_sitter_php::LANGUAGE_PHP.into(),
        Language::Scala => tree_sitter_scala::LANGUAGE.into(),
        Language::CSharp => tree_sitter_c_sharp::LANGUAGE.into(),
        Language::Ruby => tree_sitter_ruby::LANGUAGE.into(),
        Language::None => return None,
    })
}

/// Resolve the normalized structural adapter registered for a language
/// without constructing a workspace analyzer.
pub(crate) fn structural_spec_for(
    language: Language,
) -> Option<&'static dyn structural::StructuralSpec> {
    Some(match language {
        Language::Java => &java::structural::JAVA_STRUCTURAL_SPEC,
        Language::Go => &go::structural::GO_STRUCTURAL_SPEC,
        Language::Cpp => &cpp::structural::CPP_STRUCTURAL_SPEC,
        Language::JavaScript => &js_ts::structural::JAVASCRIPT_STRUCTURAL_SPEC,
        Language::TypeScript => &js_ts::structural::TYPESCRIPT_STRUCTURAL_SPEC,
        Language::Python => &python::structural::PYTHON_STRUCTURAL_SPEC,
        Language::Rust => &rust::structural::RUST_STRUCTURAL_SPEC,
        Language::Php => &php::structural::PHP_STRUCTURAL_SPEC,
        Language::Scala => &scala::structural::SCALA_STRUCTURAL_SPEC,
        Language::CSharp => &csharp::structural::CSHARP_STRUCTURAL_SPEC,
        Language::Ruby => &ruby::structural::RUBY_STRUCTURAL_SPEC,
        Language::None => return None,
    })
}
