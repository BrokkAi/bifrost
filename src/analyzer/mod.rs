mod capabilities;
mod clone_detection;
pub mod cognitive_complexity;
#[cfg(test)]
mod cognitive_complexity_tests;
pub(crate) mod common;
mod config;
mod cpp;
mod csharp_analyzer;
mod go_analyzer;
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
mod rust_analyzer;
mod scala;
mod source_content;
pub(crate) mod symbol_lookup;
pub(crate) mod tree_sitter_analyzer;
mod typescript;
pub mod usages;
mod workspace;

pub use capabilities::{
    CapabilityProvider, ImportAnalysisProvider, TestDetectionProvider, TypeAliasProvider,
    TypeHierarchyProvider,
};
pub(crate) use capabilities::{build_reverse_import_index, direct_descendants_via_ancestors};
pub use config::AnalyzerConfig;
pub use cpp::CppAnalyzer;
pub(crate) use cpp::{
    node_text as cpp_node_text, normalize_cpp_whitespace, parse_quoted_include,
    resolve_include_targets,
};
pub use csharp_analyzer::CSharpAnalyzer;
pub use go_analyzer::GoAnalyzer;
pub use i_analyzer::IAnalyzer;
pub use java::JavaAnalyzer;
pub use javascript::JavascriptAnalyzer;
pub(crate) use js_ts::resolve_js_ts_module_specifier;
pub use model::{
    CloneSmell, CloneSmellWeights, CodeBaseMetrics, CodeUnit, CodeUnitType, CommentDensityStats,
    DeclarationInfo, DeclarationKind, ExceptionHandlingSmell, ExceptionSmellWeights, ImportInfo,
    Language, MaintainabilitySizeSmell, MaintainabilitySizeSmellWeights, ParseError,
    ParseErrorKind, ProjectFile, Range, TestAssertionSmell, TestAssertionWeights,
    metrics_from_declarations,
};
pub use multi_analyzer::{AnalyzerDelegate, MultiAnalyzer};
pub use php::{
    PhpAnalyzer, PhpUseAliases, parse_php_use_aliases, parse_php_use_aliases_by_kind,
    parse_php_use_aliases_from_source, php_namespace_to_fq,
};
pub use project::{
    DEFAULT_MAX_OVERLAY_BYTES, FilesystemProject, OverlayProject, Project, TestProject,
};
pub use python::PythonAnalyzer;
pub use rust_analyzer::RustAnalyzer;
pub use scala::ScalaAnalyzer;
pub use source_content::SourceContent;
pub use tree_sitter_analyzer::{LanguageAdapter, TreeSitterAnalyzer};
pub use typescript::TypescriptAnalyzer;
pub use workspace::{EmptyAnalyzer, WorkspaceAnalyzer};
