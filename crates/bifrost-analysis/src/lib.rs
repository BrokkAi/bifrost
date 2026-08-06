//! Protocol-neutral analysis engine for Bifrost hosts and runtimes.
//!
//! Internal implementation detail of `brokk-bifrost`; no stability guarantees --
//! depend on `brokk-bifrost` instead.
//!
//! The foundation layer -- the analyzer data model, the project abstraction,
//! the structural kind/role vocabulary, and the process-wide utilities -- lives
//! in [`brokk_bifrost_core`]. Every item it owns is re-exported here at its
//! historical path, so a consumer never has to know which side of the seam a
//! name came from.

pub mod analyzer;
// `cache_gc` and `path_utils` keep a module here rather than a re-export: each
// has a small tail that needs an `AnalyzerStore` or an `IAnalyzer`, which core
// cannot see. Both re-export their core half at the top of the file.
pub mod cache_gc;
pub mod code_quality;
pub mod diff_analysis;
pub mod file_tools;
pub mod model_context;
pub mod navigation;
pub mod path_utils;
pub mod process;
pub mod relevance;
pub mod searchtools;
pub mod searchtools_render;
pub mod sexp;
pub mod summary;
pub mod symbol_rename;
#[cfg(test)]
mod test_support;
pub mod workspace_document;

pub use brokk_bifrost_core::{
    cache_db, cancellation, compact_graph, define_identifier, git_file, gitblob, hash,
    path_normalization, profiling, schema_version, text_utils, util,
};

pub use analyzer::structural::{
    CodeQuery, CodeQueryExecutionLimits, CodeQueryExecutionMode, CodeQueryExplain,
    CodeQueryProfile, CodeQueryResponse, execute_request, execute_request_with_cancellation,
    execute_request_with_limits,
};
pub use analyzer::usages;
pub use analyzer::{
    AnalyzerConfig, AnalyzerDelegate, BIFROST_IGNORE_FILE_NAME, CSharpAnalyzer, CapabilityProvider,
    CloneSmell, CloneSmellWeights, CodeBaseMetrics, CodeUnit, CodeUnitIndex, CodeUnitType,
    CppAnalyzer, DeclarationInfo, DeclarationKind, DependencyPackActivationOutcome,
    DependencyPackEcosystem, DependencyPackEcosystemOutcome, DependencyPackWorkspaceContext,
    EmptyAnalyzer, ExceptionHandlingAnalysis, ExceptionHandlingSmell, ExceptionSmellWeights,
    FileSetProject, FilesystemProject, GoAnalyzer, IAnalyzer, ImportAnalysisProvider, ImportInfo,
    ImportReachability, IngestedSource, JavaAnalyzer, JavascriptAnalyzer, JvmAnalyzerConfig,
    JvmDependencyDiscoveryConfig, JvmDependencyDiscoveryMode, JvmExternalArtifact,
    JvmExternalDependencies, JvmMavenCoordinate, JvmStandardLibraryDiscoveryConfig, KotlinAnalyzer,
    Language, MultiAnalyzer, MultiRootProject, OverlayProject, ParseError, ParseErrorKind,
    PhpAnalyzer, Project, ProjectFile, PythonAnalyzer, PythonSemanticModelWorkspaceContext, Range,
    RubyAnalyzer, RubyAnalyzerConfig, RubyDependencyApiEvidence, RubyDependencyPackAdapter,
    RubyGemApiArtifact, RustAnalyzer, RustAnalyzerConfig, RustDependencyApiEvidence,
    RustDependencyPackAdapter, RustPackageApiArtifact, RustSelectedTarget, RustdocJsonPackProducer,
    ScalaAnalyzer, SourceContent, SourceIngestionError, SourceIngestionKind, TestAssertionAnalysis,
    TestAssertionSmell, TestAssertionWeights, TestDetectionProvider, TestProject,
    TreeSitterAnalyzer, TypeAliasProvider, TypeHierarchyProvider, TypescriptAnalyzer,
    WorkspaceAnalyzer, WorkspaceFileListingCache, collect_workspace_files, ingest_source_bytes,
    resolve_ruby_semantic_pack_dependencies, resolve_rust_semantic_pack_dependencies,
};
#[cfg(any(test, feature = "test-support"))]
pub use analyzer::{
    reset_rust_tree_parse_counters_for_test, rust_tree_parse_count_for_test,
    rust_tree_parse_request_count_for_test, rust_tree_parsed_bytes_for_test,
};
pub use cancellation::CancellationToken;
pub use navigation::NavigationOperation;
pub use summary::{RenderedSummary, SummaryInput, summarize_inputs};
