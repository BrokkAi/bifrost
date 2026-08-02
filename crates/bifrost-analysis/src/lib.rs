//! Protocol-neutral analysis engine for Bifrost hosts and runtimes.

pub mod analyzer;
pub mod cache_db;
pub mod cache_gc;
pub mod cancellation;
pub mod code_quality;
pub mod compact_graph;
pub mod diff_analysis;
pub mod file_tools;
pub mod git_file;
pub mod gitblob;
pub mod hash;
pub mod model_context;
pub mod navigation;
#[cfg(feature = "nlp")]
pub mod nlp;
pub mod path_normalization;
pub mod path_utils;
pub mod process;
pub mod profiling;
pub mod reference_differential;
pub mod relevance;
pub mod schema_version;
pub mod searchtools;
pub mod searchtools_render;
pub mod sexp;
pub mod summary;
pub mod symbol_rename;
#[cfg(test)]
mod test_support;
pub mod text_utils;
pub mod util;
pub mod workspace_document;

pub use analyzer::policy;
pub use analyzer::structural::{
    CodeQuery, CodeQueryExecutionLimits, CodeQueryExecutionMode, CodeQueryExplain,
    CodeQueryProfile, CodeQueryResponse, execute_request, execute_request_with_cancellation,
    execute_request_with_limits,
};
pub use analyzer::usages;
pub use analyzer::{
    AnalyzerConfig, AnalyzerDelegate, CSharpAnalyzer, CapabilityProvider, CloneSmell,
    CloneSmellWeights, CodeBaseMetrics, CodeUnit, CodeUnitType, CppAnalyzer, DeclarationInfo,
    DeclarationKind, EmptyAnalyzer, ExceptionHandlingAnalysis, ExceptionHandlingSmell,
    ExceptionSmellWeights, FileSetProject, FilesystemProject, GoAnalyzer, IAnalyzer,
    ImportAnalysisProvider, ImportInfo, JavaAnalyzer, JavascriptAnalyzer, JvmAnalyzerConfig,
    JvmDependencyDiscoveryConfig, JvmDependencyDiscoveryMode, JvmExternalArtifact,
    JvmExternalDependencies, JvmMavenCoordinate, JvmStandardLibraryDiscoveryConfig, KotlinAnalyzer,
    Language, MultiAnalyzer, MultiRootProject, OverlayProject, ParseError, ParseErrorKind,
    PhpAnalyzer, Project, ProjectFile, PythonAnalyzer, Range, RubyAnalyzer, RustAnalyzer,
    RustAnalyzerConfig, RustDependencyApiEvidence, RustPackageApiArtifact, RustSelectedTarget,
    ScalaAnalyzer, SourceContent, TestAssertionAnalysis, TestAssertionSmell, TestAssertionWeights,
    TestDetectionProvider, TestProject, TreeSitterAnalyzer, TypeAliasProvider,
    TypeHierarchyProvider, TypescriptAnalyzer, WorkspaceAnalyzer, WorkspaceFileListingCache,
    collect_workspace_files, reset_rust_tree_parse_counters_for_test,
    rust_tree_parse_count_for_test, rust_tree_parse_request_count_for_test,
    rust_tree_parsed_bytes_for_test,
};
pub use cancellation::CancellationToken;
pub use navigation::NavigationOperation;
pub use summary::{RenderedSummary, SummaryInput, summarize_inputs};
