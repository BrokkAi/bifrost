#[cfg(test)]
pub(crate) mod benchmark_provenance;
pub(crate) mod bounded_output;
pub mod canonical_hash;
mod capabilities;
mod clone_detection;
pub mod cognitive_complexity;
#[cfg(test)]
mod cognitive_complexity_tests;
mod comment_density;
pub mod common;
mod complete_value_cache;
mod cpp;
mod csharp;
pub mod dataflow;
pub mod declaration_range;
pub(crate) mod exception_handling;
mod global_usage_definition_index;
mod go;
mod i_analyzer;
mod java;
mod javascript;
mod js_ts;
pub(crate) mod jvm;
mod kotlin;
pub(crate) mod languages;
pub mod lexical_definitions;
mod multi_analyzer;
mod php;
mod pool_memo;
mod python;
pub mod reference_candidates;
mod ruby;
mod rust;
mod scala;
pub mod semantic;
pub mod semantic_model;
mod source_ingestion;
pub mod store;
pub mod structural;
pub(crate) mod symbol_lookup;
pub mod taint;
pub(crate) mod test_assertions;
pub mod tree_sitter_analyzer;
pub(crate) mod tree_walk;
pub(crate) mod type_relations;
mod typescript;
pub mod typestate;
mod usage_facts;
pub mod usages;
pub mod value_flow;
pub(crate) mod weighted_cache;
mod work_budget;
mod workspace;

// The model layer moved to `brokk-bifrost-core` (the analyzer data model, the
// project abstraction, identifier/dense-id machinery, the language-blind half
// of `common`). Re-exported here at the exact paths they had, so nothing above
// this crate has to know where they now live: the `pub use <module>::{...}`
// blocks below read the same as when the modules were declared here.
// Each keeps the visibility its `mod` declaration had, so the seam does not
// quietly widen this crate's public surface.
use brokk_bifrost_core::analyzer::{code_unit_index, config, model, project, source_content};
pub(crate) use brokk_bifrost_core::analyzer::{dense_id, fq_name, semantic_diagnostics};
pub use brokk_bifrost_core::analyzer::{identifier, test_paths};
pub use code_unit_index::CodeUnitIndex;
pub(crate) use code_unit_index::default_parent_fq_name;

pub use capabilities::{
    CapabilityProvider, ImportAnalysisProvider, TestDetectionProvider, TypeAliasProvider,
    TypeHierarchyProvider,
};
pub(crate) use capabilities::{
    DirectDescendantIndex, build_direct_descendant_index, build_reverse_file_index,
    build_reverse_import_index, memoized_reverse_file_index, memoized_reverse_import_index,
    resolve_imported_files_from_infos,
};
pub use config::{
    AnalyzerConfig, CSharpAnalyzerConfig, GoAnalyzerConfig, GoDependencyDiscoveryConfig,
    JsTsAnalyzerConfig, JsTsDependencyDiscoveryConfig, JvmAnalyzerConfig,
    JvmDependencyDiscoveryConfig, JvmDependencyDiscoveryMode, JvmExternalArtifact,
    JvmExternalArtifactOrigin, JvmExternalDependencies, JvmMavenCoordinate,
    JvmStandardLibraryDiscoveryConfig, PythonAnalyzerConfig, PythonEnvironmentConfig,
    PythonEnvironmentLimits, RubyAnalyzerConfig, RubyDependencyApiEvidence, RubyGemApiArtifact,
    RustAnalyzerConfig, RustDependencyApiEvidence, RustPackageApiArtifact, RustSelectedTarget,
};
pub use cpp::CppAnalyzer;
pub(crate) use cpp::{
    CppCallableUnitRole, CppOccurrenceClassifier, CppOccurrenceRole, IncludeTargetIndex,
    cpp_callable_definitions_share_identity_evidence, cpp_callable_unit_role,
    cpp_indexed_callable_linkage, cpp_template_term, include_paths as cpp_include_paths,
    node_text as cpp_node_text, normalize_cpp_whitespace, recovered_exported_class_has_body,
    resolve_include_targets, resolve_include_targets_with_index,
};
pub use csharp::CSharpAnalyzer;
pub use csharp::external::{
    CSharpAssemblyPackProducer, CSharpDependencyPackAdapter, CSharpExternalDeclarationIndex,
    CSharpExternalDeclarationSource, CSharpExternalMember, CSharpExternalMemberKind,
    CSharpExternalType, CSharpExternalTypeKind, CSharpVisibility,
    resolve_csharp_semantic_pack_dependencies,
};
pub(crate) use csharp::{
    CSharpMemberName, csharp_attribute_name_node, csharp_attribute_terminal_name,
    csharp_attribute_type_names, csharp_callable_arity, csharp_conditional_member_access,
    csharp_constant_pattern_type_candidate, csharp_member_access_type_receiver, csharp_member_name,
    csharp_method_generic_arity, csharp_nameof_type_candidates, csharp_normalize_full_name,
    csharp_signature_return_type, csharp_source_identifier, csharp_type_leftmost_identifier,
    csharp_type_node_identity, csharp_type_reference_root, csharp_type_terminal_identifier,
    csharp_unqualified_invocation_for_name, csharp_using_directive_is_global,
    csharp_using_directive_is_static, csharp_using_directive_namespace,
    csharp_using_directive_target,
};
pub use csharp::{csharp_source_name_segment, strip_csharp_generic_arity};
pub use fq_name::FqName;
pub(crate) use global_usage_definition_index::{
    AnalyzerDefinitionLookup, BoundedDefinitionLookup, ForwardQueryProvider,
    impl_forward_query_provider,
};
pub use global_usage_definition_index::{DefinitionIndexHandle, GlobalUsageDefinitionIndex};
pub(crate) use go::{
    GO_MODULE_SCOPE_SEGMENT,
    packages::{GoModuleRoot, go_internal_import_allowed, go_module_roots},
};
pub use go::{GoAnalyzer, GoDependencyPackAdapter, resolve_go_semantic_pack_dependencies};
pub use i_analyzer::AnalyzerQueryScope;
pub use i_analyzer::AnalyzerStreamingFileScope;
pub use i_analyzer::{
    AnalyzerQueryContext, AnalyzerSnapshotCaches, IAnalyzer, QueryBatch, SearchSymbolCandidates,
    SearchSymbolPatternBatch, WorkspaceFileIndex, WorkspaceFileIndexCell,
};
#[cfg(any(test, feature = "test-support"))]
pub use i_analyzer::{AnalyzerTestHooks, NoOpAnalyzerTestHooks};
pub use java::JavaAnalyzer;
pub use javascript::JavascriptAnalyzer;
pub(crate) use js_ts::{AliasResolver, resolve_js_ts_module_specifier};
pub use js_ts::{
    JsTsDependencyPackAdapter, TypeScriptDeclarationPackProducer,
    resolve_js_ts_semantic_pack_dependencies,
};
pub use jvm::external::{JvmDependencyPackAdapter, resolve_jvm_semantic_pack_dependencies};
pub use jvm::java_artifact::JavaJarPackProducer;
pub use jvm::jdk_artifact::{JdkSourceArchiveLayout, JdkSourceArchivePackProducer};
pub use jvm::kotlin_artifact::KotlinSourceJarPackProducer;
pub use jvm::scala_artifact::ScalaSourceJarPackProducer;
pub use kotlin::KotlinAnalyzer;
pub use model::SemanticDiagnostic;
pub use model::{
    CallableArity, CloneSmell, CloneSmellWeights, CodeBaseMetrics, CodeUnit, CodeUnitType,
    CommentDensityStats, DeclarationInfo, DeclarationKind, DispatchExtensibility,
    ExceptionHandlingAnalysis, ExceptionHandlingSmell, ExceptionSmellWeights, ImportInfo, Language,
    MaintainabilitySizeSmell, MaintainabilitySizeSmellWeights, ParameterMetadata, ParseError,
    ParseErrorKind, ProjectFile, Range, RubyMethodDispatchMode, SearchSymbolCandidate,
    SignatureMetadata, StructuredImportPath, StructuredImportPathKind, StructuredImportScope,
    StructuredTypeIdentity, StructuredTypeName, SummaryFileProjection, TestAssertionAnalysis,
    TestAssertionSmell, TestAssertionWeights, metrics_from_declarations,
};
pub(crate) use model::{
    CallableLinkage, CppTemplateAliasTargetMetadata, CppTemplateExpression, CppTemplateMetadata,
    CppTemplateParameterKind, CppTemplateParameterMetadata, CppTemplateTerm,
};
pub use multi_analyzer::resolve_analyzer;
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
    BIFROST_IGNORE_FILE_NAME, DEFAULT_MAX_OVERLAY_BYTES, FileSetProject, FilesystemProject,
    MultiRootProject, OverlayProject, OverlayRevision, Project, ProjectSourceOrigin,
    ProjectSourceSnapshot, TestProject, WorkspaceFileListingCache, collect_workspace_files,
};
pub(crate) use python::{
    ModuleBindingEvent, ModuleBindingEventKind, ModuleBindingTimeline, PythonScopeFacts,
};
pub use python::{
    PythonAnalyzer, PythonImportBinding,
    external::{
        PythonArtifactPackProducer, PythonDependencyPackAdapter,
        resolve_python_semantic_pack_dependencies,
    },
    parse_python_import_bindings, parse_python_import_infos,
};
pub use ruby::RubyAnalyzer;
pub(crate) use ruby::RubySemanticFacts;
pub use ruby::{RubyDependencyPackAdapter, resolve_ruby_semantic_pack_dependencies};
pub use rust::rust_is_field_declaration_name;
pub use rust::{
    RustAnalyzer, RustDependencyPackAdapter, RustReferenceContext, RustdocJsonPackProducer,
    reset_rust_tree_parse_counters_for_test, resolve_rust_semantic_pack_dependencies,
    rust_tree_parse_count_for_test, rust_tree_parse_request_count_for_test,
    rust_tree_parsed_bytes_for_test,
};
pub use scala::ScalaAnalyzer;
pub(crate) use scala::scala_parenthesized_arity;
pub use source_content::SourceContent;
pub use source_ingestion::{
    IngestedSource, SourceIngestionError, SourceIngestionKind, ingest_source_bytes,
};
pub(crate) use tree_sitter_analyzer::{
    AnalyzerStoreContext, BulkFileStateSource, default_store_context, persistent_store_context,
};
pub use tree_sitter_analyzer::{
    BuildProgress, BuildProgressEvent, BuildProgressPhase, LanguageAdapter, TreeSitterAnalyzer,
};
pub use typescript::TypescriptAnalyzer;
pub(crate) use usage_facts::UsageFactsIndex;
pub use workspace::{
    EmptyAnalyzer, PythonSemanticModelActivationOutcome, PythonSemanticModelWorkspaceContext,
    WorkspaceAnalyzer,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParserFlavor {
    Default,
    TypeScriptTsx,
}

/// A source language plus the parser dialect needed to interpret one file.
///
/// Most languages have one grammar. TypeScript is the exception because `.ts`
/// and `.tsx` files use distinct tree-sitter grammars while sharing the same
/// normalized language adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LanguageDialect {
    Standard(Language),
    TypeScriptTsx,
}

impl LanguageDialect {
    /// Parse a user-facing language or dialect label.
    pub fn from_config_label(label: &str) -> Option<Self> {
        let normalized = label
            .trim()
            .trim_start_matches('.')
            .to_ascii_lowercase()
            .replace(['_', '-'], "");
        if matches!(
            normalized.as_str(),
            "tsx" | "typescriptreact" | "typescripttsx"
        ) {
            return Some(Self::TypeScriptTsx);
        }
        Language::from_config_label(label).map(Self::Standard)
    }

    /// Select the parser dialect used by the indexed analyzer for `path`.
    pub fn for_path(language: Language, path: &std::path::Path) -> Self {
        if parser_flavor_for_path(language, path) == ParserFlavor::TypeScriptTsx {
            Self::TypeScriptTsx
        } else {
            Self::Standard(language)
        }
    }

    pub const fn language(self) -> Language {
        match self {
            Self::Standard(language) => language,
            Self::TypeScriptTsx => Language::TypeScript,
        }
    }

    /// Canonical durable identity label. Unlike [`Self::config_label`], this
    /// makes the TypeScript language explicit rather than using the `tsx`
    /// shorthand.
    pub fn stable_label(self) -> &'static str {
        match self {
            Self::Standard(language) => language.config_label(),
            Self::TypeScriptTsx => "typescript-tsx",
        }
    }

    /// Short user-facing configuration label retained by Rune IR and the CLI.
    pub fn config_label(self) -> &'static str {
        match self {
            Self::Standard(language) => language.config_label(),
            Self::TypeScriptTsx => "tsx",
        }
    }

    pub fn config_labels() -> impl Iterator<Item = &'static str> {
        Language::ANALYZABLE
            .iter()
            .map(|language| language.config_label())
            .chain(std::iter::once("tsx"))
    }

    pub(crate) fn parser_language(self) -> Option<tree_sitter::Language> {
        let flavor = match self {
            Self::Standard(_) => ParserFlavor::Default,
            Self::TypeScriptTsx => ParserFlavor::TypeScriptTsx,
        };
        parser_language_for_flavor(self.language(), flavor)
    }
}

impl From<Language> for LanguageDialect {
    fn from(language: Language) -> Self {
        Self::Standard(language)
    }
}

impl std::fmt::Display for LanguageDialect {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.stable_label())
    }
}

/// Resolve the default parser grammar registered for a language.
pub fn parser_language_for(language: Language) -> Option<tree_sitter::Language> {
    parser_language_for_flavor(language, ParserFlavor::Default)
}

/// Resolve a parser grammar from the canonical language registry.
pub(crate) fn parser_language_for_flavor(
    language: Language,
    flavor: ParserFlavor,
) -> Option<tree_sitter::Language> {
    languages::language_support(language).map(|support| support.parser_language(flavor))
}

/// Resolve the parser grammar used by the indexed analyzer for a specific path.
pub(crate) fn parser_language_for_path(
    language: Language,
    path: &std::path::Path,
) -> Option<tree_sitter::Language> {
    parser_language_for_flavor(language, parser_flavor_for_path(language, path))
}

pub(crate) fn parser_flavor_for_path(language: Language, path: &std::path::Path) -> ParserFlavor {
    if language == Language::TypeScript
        && path
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|extension| extension.eq_ignore_ascii_case("tsx"))
    {
        ParserFlavor::TypeScriptTsx
    } else {
        ParserFlavor::Default
    }
}

/// Resolve the normalized structural adapter registered for a language
/// without constructing a workspace analyzer.
pub(crate) fn structural_spec_for(
    language: Language,
) -> Option<&'static dyn structural::StructuralSpec> {
    languages::language_support(language).map(languages::LanguageSupport::structural_spec)
}
