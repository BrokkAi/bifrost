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
mod definition_lookup_index;
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
    memoized_reverse_file_index, memoized_reverse_import_index,
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
    csharp_as_expression_type_operand, csharp_normalize_full_name, csharp_signature_arity,
    csharp_signature_return_type, csharp_source_identifier, csharp_source_name_segment,
    csharp_type_node_identity, csharp_using_directive_is_static,
};
pub use definition_lookup_index::DefinitionLookupIndex;
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
