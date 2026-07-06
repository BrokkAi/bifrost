mod capabilities;
mod clone_detection;
pub mod cognitive_complexity;
#[cfg(test)]
mod cognitive_complexity_tests;
pub(crate) mod common;
mod config;
mod cpp;
mod csharp;
mod definition_lookup_index;
mod go;
mod i_analyzer;
mod java;
mod javascript;
mod js_ts;
mod model;
mod multi_analyzer;
pub mod persistence;
mod php;
mod project;
mod python;
mod ruby;
mod rust;
mod scala;
pub(crate) mod semantic_diagnostics;
mod source_content;
pub mod structural;
pub(crate) mod symbol_lookup;
pub(crate) mod tree_sitter_analyzer;
pub(crate) mod type_relations;
mod typescript;
pub mod usages;
mod workspace;

pub use capabilities::{
    CapabilityProvider, ImportAnalysisProvider, TestDetectionProvider, TypeAliasProvider,
    TypeHierarchyProvider,
};
pub(crate) use capabilities::{
    build_direct_descendant_index, build_reverse_file_index, build_reverse_import_index,
};
pub use config::{
    AnalyzerConfig, JavaAnalyzerConfig, JavaExternalArtifact, JavaExternalDependencies,
    JavaMavenCoordinate,
};
pub use cpp::CppAnalyzer;
pub(crate) use cpp::{
    include_paths as cpp_include_paths, node_text as cpp_node_text, normalize_cpp_whitespace,
    resolve_include_targets, resolve_include_targets_with_unique_fallback,
};
pub use csharp::CSharpAnalyzer;
pub use definition_lookup_index::DefinitionLookupIndex;
pub use go::GoAnalyzer;
pub use i_analyzer::IAnalyzer;
pub use java::JavaAnalyzer;
pub use javascript::JavascriptAnalyzer;
pub(crate) use js_ts::{AliasResolver, resolve_js_ts_module_specifier};
pub(crate) use model::SemanticDiagnostic;
pub use model::{
    CloneSmell, CloneSmellWeights, CodeBaseMetrics, CodeUnit, CodeUnitType, CommentDensityStats,
    DeclarationInfo, DeclarationKind, ExceptionHandlingSmell, ExceptionSmellWeights, ImportInfo,
    Language, MaintainabilitySizeSmell, MaintainabilitySizeSmellWeights, ParameterMetadata,
    ParseError, ParseErrorKind, ProjectFile, Range, SignatureMetadata, TestAssertionSmell,
    TestAssertionWeights, metrics_from_declarations,
};
pub(crate) use multi_analyzer::resolve_analyzer;
pub use multi_analyzer::{AnalyzerDelegate, MultiAnalyzer};
pub use php::{
    PhpAnalyzer, PhpUseAliases, parse_php_use_aliases, parse_php_use_aliases_by_kind,
    parse_php_use_aliases_from_source, php_namespace_to_fq,
};
pub(crate) use php::{
    PhpFileContext, resolve_php_constant, resolve_php_function, resolve_php_type,
};
pub use project::{
    DEFAULT_MAX_OVERLAY_BYTES, FileSetProject, FilesystemProject, MultiRootProject, OverlayProject,
    Project, TestProject, collect_workspace_files,
};
pub use python::PythonAnalyzer;
pub use ruby::RubyAnalyzer;
pub use rust::{RustAnalyzer, RustReferenceContext};
pub use scala::ScalaAnalyzer;
pub use source_content::SourceContent;
pub use tree_sitter_analyzer::{
    BuildProgress, BuildProgressEvent, BuildProgressPhase, LanguageAdapter, TreeSitterAnalyzer,
};
pub use typescript::TypescriptAnalyzer;
pub use workspace::{EmptyAnalyzer, WorkspaceAnalyzer};
