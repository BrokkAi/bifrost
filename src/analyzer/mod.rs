mod capabilities;
mod clone_detection;
pub mod cognitive_complexity;
#[cfg(test)]
mod cognitive_complexity_tests;
mod config;
mod cpp_analyzer;
mod csharp_analyzer;
mod go_analyzer;
mod i_analyzer;
mod java_analyzer;
mod javascript_analyzer;
mod model;
mod multi_analyzer;
pub mod persistence;
mod php_analyzer;
mod project;
mod python_analyzer;
mod rust_analyzer;
mod scala_analyzer;
mod source_content;
pub(crate) mod symbol_lookup;
pub(crate) mod tree_sitter_analyzer;
mod typescript_analyzer;
mod workspace;

pub use capabilities::{
    CapabilityProvider, ImportAnalysisProvider, TestDetectionProvider, TypeAliasProvider,
    TypeHierarchyProvider,
};
pub(crate) use capabilities::{build_reverse_import_index, direct_descendants_via_ancestors};
pub use config::AnalyzerConfig;
pub use cpp_analyzer::CppAnalyzer;
pub(crate) use cpp_analyzer::{
    node_text as cpp_node_text, normalize_cpp_whitespace, parse_quoted_include,
    resolve_include_targets,
};
pub use csharp_analyzer::CSharpAnalyzer;
pub use go_analyzer::GoAnalyzer;
pub use i_analyzer::IAnalyzer;
pub use java_analyzer::JavaAnalyzer;
pub use javascript_analyzer::JavascriptAnalyzer;
pub(crate) use javascript_analyzer::resolve_js_ts_module_specifier;
pub use model::{
    CloneSmell, CloneSmellWeights, CodeBaseMetrics, CodeUnit, CodeUnitType, CommentDensityStats,
    DeclarationInfo, DeclarationKind, ExceptionHandlingSmell, ExceptionSmellWeights, ImportInfo,
    Language, MaintainabilitySizeSmell, MaintainabilitySizeSmellWeights, ParseError,
    ParseErrorKind, ProjectFile, Range, TestAssertionSmell, TestAssertionWeights,
    metrics_from_declarations,
};
pub use multi_analyzer::{AnalyzerDelegate, MultiAnalyzer};
pub use php_analyzer::{
    PhpAnalyzer, PhpUseAliases, parse_php_use_aliases, parse_php_use_aliases_by_kind,
    parse_php_use_aliases_from_source, php_namespace_to_fq,
};
pub use project::{
    DEFAULT_MAX_OVERLAY_BYTES, FilesystemProject, OverlayProject, Project, TestProject,
};
pub use python_analyzer::PythonAnalyzer;
pub use rust_analyzer::RustAnalyzer;
pub use scala_analyzer::ScalaAnalyzer;
pub use source_content::SourceContent;
pub use tree_sitter_analyzer::{LanguageAdapter, TreeSitterAnalyzer};
pub use typescript_analyzer::TypescriptAnalyzer;
pub use workspace::{EmptyAnalyzer, WorkspaceAnalyzer};
