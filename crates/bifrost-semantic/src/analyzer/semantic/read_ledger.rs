use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;

use crate::analyzer::semantic::content_identity::WorkspaceContentIdentity;

use crate::analyzer::semantic::invalidation::DerivedArtifactId;

use crate::analyzer::semantic::ids::StableDigest;

use brokk_bifrost_core::analyzer::model::{CodeUnit, CodeUnitType};

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::analyzer::model::Range;

use brokk_bifrost_core::path_utils::rel_path_string;
use git2::Oid;
use serde::{Deserialize, Serialize};

/// Domain for one read key's canonical encoding.
#[doc(hidden)]
pub const READ_KEY_DOMAIN: &[u8] = b"bifrost-read-ledger:key:v1";

/// The per-file fact index families a name-keyed store lookup can consult.
///
/// Closed on purpose: a new family is a new funnel, and a funnel nobody named
/// is a funnel nobody verifies. The variants enumerate the analyzer-side
/// store lookup families whose reads the ledger verifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IndexFamily {
    /// A definition looked up by its exact qualified name.
    DefinitionExact,
    /// A definition looked up by the normalized tail of its qualified name.
    DefinitionNormalizedTail,
    /// A declaration looked up by a parsed identifier or short name.
    DefinitionIdentifier,
    /// A file looked up by an identifier its parsed references mention.
    ReferenceIdentifier,
    /// A file looked up by a structured segment of one of its import paths.
    ImportPathSegment,
    /// The existence of a package name in the workspace.
    PackageMembership,
    /// The raw supertypes recorded for one code unit.
    Supertype,
    /// The supertype lookup paths recorded for one code unit.
    SupertypeLookupPath,
    /// A path-addressed module or symbol looked up by its qualified name.
    PathSymbol,
}

impl IndexFamily {
    /// The label used in the canonical encoding and in diagnostics. Changing a
    /// label rotates every digest that contains it, which is why it is stated
    /// once here rather than derived from the variant name.
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::DefinitionExact => "definition_exact",
            Self::DefinitionNormalizedTail => "definition_normalized_tail",
            Self::DefinitionIdentifier => "definition_identifier",
            Self::ReferenceIdentifier => "reference_identifier",
            Self::ImportPathSegment => "import_path_segment",
            Self::PackageMembership => "package_membership",
            Self::Supertype => "supertype",
            Self::SupertypeLookupPath => "supertype_lookup_path",
            Self::PathSymbol => "path_symbol",
        }
    }
}

/// Closed workspace-authority families. Stable labels are never reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WorkspaceFactFamily {
    CSharpDeadCodeUsageEdges,
    CSharpReachability,
    CSharpNamespaceByFile,
    CSharpUsingNamespaces,
    CSharpFileUsingNamespaces,
    CSharpNamespaceExists,
    CSharpPersistedFqnCandidates,
    CSharpUsingAliases,
    CSharpImportedCodeUnits,
    CSharpReferencingFiles,
    CSharpDirectDescendantIndex,
    CSharpReverseImportIndex,
    CSharpImplicitReferenceIndex,
    CSharpFileDependenciesByNamespace,
    CSharpHierarchyTestFiles,
    CSharpGlobalUsingNamespaces,
    CSharpSortedGlobalUsingNamespaces,
    CSharpGlobalUsingAliases,
    CSharpGlobalStaticUsingTypeNames,
    CSharpGlobalStaticUsingTypes,
    CSharpUsageGlobalStaticUsingTypes,
    CSharpCompilationConfiguration,
    CSharpExternalDeclarations,
    GoWorkspaceIndexes,
    GoWorkspacePaths,
    GoImportFacts,
    GoReverseImports,
    GoBuildSelection,

    CppClassRanges,
    CppExternalHeaderClosures,
    CppCompileContexts,
    CppDirectDescendants,
    CppTransitiveReverseTranslationUnits,
    CppReverseIncludes,
    CppReconciledDefinitions,
    CppReconcileCandidates,
    CppHeaderLanguageAttribution,
    CppHeaderReadings,
    CppClassDeclarationStrength,
    CppIncludeReachability,
    CppReferencingFiles,
    CppOverwrittenCandidates,
    CppImportedCodeUnits,
    CppIncludeTargets,
    RubyDirectDescendants,
    RubyReverseImports,
    RubyAutoloadConstants,
    RubyCanonicalSourcesReady,
    RubyZeitwerkConventions,
    RubyZeitwerkAutoloadFiles,
    RubyZeitwerkConsumerFiles,
    RubyZeitwerkAutoloadCodeUnits,
    RubyMixinRelations,
    RubySemanticFacts,
    RubyTypesByIdentifier,
    PhpDirectDescendants,
    PhpReverseImports,
    PhpComposerAutoload,
    ProtocolSummaries,
    FieldSlots,
    JsTsUsageIndex,
    PythonModuleSpellings,
    PythonDescendants,
    PythonReverseImports,
    PythonUsageIndex,
    PythonSavedDefaults,
    PythonModuleMemberMutation,
    PythonClassMemberMutation,
    PythonEnvironmentBinding,
    JsTsModulePaths,
    JsTsWorkspacePackages,
    JsTsDescendants,
    JsTsProductionDescendants,
    JsTsReverseImports,
    JsTsMemberSurface,
    JsTsReceiverMembers,
    JsTsJsxPropsOwners,
    JsTsJsxComponentOwners,
    WorkspaceUsageGraph,
    JavaUsageEvidence,
    JavaImportInventory,
    JavaWorkspaceClasses,
    JavaReferencingFiles,
    JavaReverseImports,
    JavaSamePackageReferences,
    JavaDescendantIndex,
    JavaExternalDeclarations,
    KotlinReferencingFiles,
    KotlinReverseImports,
    KotlinSamePackageReferences,
    KotlinDescendantIndex,
    KotlinRealmDescendantIndex,
    KotlinFileDependencies,
    KotlinTopLevelDeclarations,
    KotlinDeadCodeEdges,
    KotlinExternalDeclarations,

    PythonExternalModuleMemberMutation,
    RuntimeRootWriteFootprint,
    JsTsExternalModuleMemberMutation,
    WorkspaceFileListing,
    DefinitionParents,
    PathSyntheticModules,
    PackageClassDeclarations,
    StructuralPostingIndex,
    RelationalFrontierAnswers,
    BoundedIdentifierCandidates,
    WorkspaceFileInventory,
    WorkspaceIgnoreRules,
    WorkspaceDirectory,
    WorkspacePathKind,
    WorkspaceAnalyzerLanguages,
    WorkspaceOverlayMembership,
    ScalaProjectTypes,
    ScalaResolvedQuerySeed,
    ScalaExternalIndex,
    ScalaImportableDeclarations,
    ScalaPackageNamespaces,
    ScalaFileDependencyIndex,
    ScalaLazyHierarchyIndex,
    ScalaTypeRelations,
    ScalaDeadCodeUsageEdges,
    ScalaReferencingFiles,
    ScalaReverseImportIndex,
    ScalaSamePackageReferenceIndex,
    JavaImportedTypeResolution,
}

impl WorkspaceFactFamily {
    pub const LABELS: &[(Self, &str)] = &[
        (
            Self::CSharpDeadCodeUsageEdges,
            "csharp_dead_code_usage_edges",
        ),
        (Self::CSharpReachability, "csharp_reachability"),
        (Self::CSharpNamespaceByFile, "csharp_namespace_by_file"),
        (Self::CSharpUsingNamespaces, "csharp_using_namespaces"),
        (
            Self::CSharpFileUsingNamespaces,
            "csharp_file_using_namespaces",
        ),
        (Self::CSharpNamespaceExists, "csharp_namespace_exists"),
        (
            Self::CSharpPersistedFqnCandidates,
            "csharp_persisted_fqn_candidates",
        ),
        (Self::CSharpUsingAliases, "csharp_using_aliases"),
        (Self::CSharpImportedCodeUnits, "csharp_imported_code_units"),
        (Self::CSharpReferencingFiles, "csharp_referencing_files"),
        (
            Self::CSharpDirectDescendantIndex,
            "csharp_direct_descendant_index",
        ),
        (
            Self::CSharpReverseImportIndex,
            "csharp_reverse_import_index",
        ),
        (
            Self::CSharpImplicitReferenceIndex,
            "csharp_implicit_reference_index",
        ),
        (
            Self::CSharpFileDependenciesByNamespace,
            "csharp_file_dependencies_by_namespace",
        ),
        (
            Self::CSharpHierarchyTestFiles,
            "csharp_hierarchy_test_files",
        ),
        (
            Self::CSharpGlobalUsingNamespaces,
            "csharp_global_using_namespaces",
        ),
        (
            Self::CSharpSortedGlobalUsingNamespaces,
            "csharp_sorted_global_using_namespaces",
        ),
        (
            Self::CSharpGlobalUsingAliases,
            "csharp_global_using_aliases",
        ),
        (
            Self::CSharpGlobalStaticUsingTypeNames,
            "csharp_global_static_using_type_names",
        ),
        (
            Self::CSharpGlobalStaticUsingTypes,
            "csharp_global_static_using_types",
        ),
        (
            Self::CSharpUsageGlobalStaticUsingTypes,
            "csharp_usage_global_static_using_types",
        ),
        (
            Self::CSharpCompilationConfiguration,
            "csharp_compilation_configuration",
        ),
        (
            Self::CSharpExternalDeclarations,
            "csharp_external_declarations",
        ),
        (Self::GoWorkspaceIndexes, "go_workspace_indexes"),
        (Self::GoWorkspacePaths, "go_workspace_paths"),
        (Self::GoImportFacts, "go_import_facts"),
        (Self::GoReverseImports, "go_reverse_imports"),
        (Self::GoBuildSelection, "go_build_selection"),
        (Self::CppClassRanges, "cpp_class_ranges"),
        (
            Self::CppExternalHeaderClosures,
            "cpp_external_header_closures",
        ),
        (Self::CppCompileContexts, "cpp_compile_contexts"),
        (Self::CppDirectDescendants, "cpp_direct_descendants"),
        (
            Self::CppTransitiveReverseTranslationUnits,
            "cpp_transitive_reverse_translation_units",
        ),
        (Self::CppReverseIncludes, "cpp_reverse_includes"),
        (Self::CppReconciledDefinitions, "cpp_reconciled_definitions"),
        (Self::CppReconcileCandidates, "cpp_reconcile_candidates"),
        (
            Self::CppHeaderLanguageAttribution,
            "cpp_header_language_attribution",
        ),
        (Self::CppHeaderReadings, "cpp_header_readings"),
        (
            Self::CppClassDeclarationStrength,
            "cpp_class_declaration_strength",
        ),
        (Self::CppIncludeReachability, "cpp_include_reachability"),
        (Self::CppReferencingFiles, "cpp_referencing_files"),
        (Self::CppOverwrittenCandidates, "cpp_overwritten_candidates"),
        (Self::CppImportedCodeUnits, "cpp_imported_code_units"),
        (Self::CppIncludeTargets, "cpp_include_targets"),
        (Self::RubyDirectDescendants, "ruby_direct_descendants"),
        (Self::RubyReverseImports, "ruby_reverse_imports"),
        (Self::RubyAutoloadConstants, "ruby_autoload_constants"),
        (
            Self::RubyCanonicalSourcesReady,
            "ruby_canonical_sources_ready",
        ),
        (Self::RubyZeitwerkConventions, "ruby_zeitwerk_conventions"),
        (
            Self::RubyZeitwerkAutoloadFiles,
            "ruby_zeitwerk_autoload_files",
        ),
        (
            Self::RubyZeitwerkConsumerFiles,
            "ruby_zeitwerk_consumer_files",
        ),
        (
            Self::RubyZeitwerkAutoloadCodeUnits,
            "ruby_zeitwerk_autoload_code_units",
        ),
        (Self::RubyMixinRelations, "ruby_mixin_relations"),
        (Self::RubySemanticFacts, "ruby_semantic_facts"),
        (Self::RubyTypesByIdentifier, "ruby_types_by_identifier"),
        (Self::PhpDirectDescendants, "php_direct_descendants"),
        (Self::PhpReverseImports, "php_reverse_imports"),
        (Self::PhpComposerAutoload, "php_composer_autoload"),
        (Self::ProtocolSummaries, "protocol_summaries"),
        (Self::FieldSlots, "field_slots"),
        (
            Self::JsTsExternalModuleMemberMutation,
            "js_ts_external_module_member_mutation",
        ),
        (Self::JsTsUsageIndex, "js_ts_usage_index"),
        (Self::PythonModuleSpellings, "python_module_spellings"),
        (Self::PythonDescendants, "python_descendants"),
        (Self::PythonReverseImports, "python_reverse_imports"),
        (Self::PythonUsageIndex, "python_usage_index"),
        (Self::PythonSavedDefaults, "python_saved_defaults"),
        (
            Self::PythonModuleMemberMutation,
            "python_module_member_mutation",
        ),
        (
            Self::PythonClassMemberMutation,
            "python_class_member_mutation",
        ),
        (Self::PythonEnvironmentBinding, "python_environment_binding"),
        (Self::JsTsModulePaths, "js_ts_module_paths"),
        (Self::JsTsWorkspacePackages, "js_ts_workspace_packages"),
        (Self::JsTsDescendants, "js_ts_descendants"),
        (
            Self::JsTsProductionDescendants,
            "js_ts_production_descendants",
        ),
        (Self::JsTsReverseImports, "js_ts_reverse_imports"),
        (Self::JsTsMemberSurface, "js_ts_member_surface"),
        (Self::JsTsReceiverMembers, "js_ts_receiver_members"),
        (Self::JsTsJsxPropsOwners, "js_ts_jsx_props_owners"),
        (Self::JsTsJsxComponentOwners, "js_ts_jsx_component_owners"),
        (Self::WorkspaceUsageGraph, "workspace_usage_graph"),
        (Self::JavaUsageEvidence, "java_usage_evidence"),
        (Self::JavaImportInventory, "java_import_inventory"),
        (Self::JavaWorkspaceClasses, "java_workspace_classes"),
        (Self::JavaReferencingFiles, "java_referencing_files"),
        (Self::JavaReverseImports, "java_reverse_imports"),
        (
            Self::JavaSamePackageReferences,
            "java_same_package_references",
        ),
        (Self::JavaDescendantIndex, "java_descendant_index"),
        (Self::JavaExternalDeclarations, "java_external_declarations"),
        (Self::KotlinReferencingFiles, "kotlin_referencing_files"),
        (Self::KotlinReverseImports, "kotlin_reverse_imports"),
        (
            Self::KotlinSamePackageReferences,
            "kotlin_same_package_references",
        ),
        (Self::KotlinDescendantIndex, "kotlin_descendant_index"),
        (
            Self::KotlinRealmDescendantIndex,
            "kotlin_realm_descendant_index",
        ),
        (Self::KotlinFileDependencies, "kotlin_file_dependencies"),
        (
            Self::KotlinTopLevelDeclarations,
            "kotlin_top_level_declarations",
        ),
        (Self::KotlinDeadCodeEdges, "kotlin_dead_code_edges"),
        (
            Self::KotlinExternalDeclarations,
            "kotlin_external_declarations",
        ),
        (
            Self::PythonExternalModuleMemberMutation,
            "python_external_module_member_mutation",
        ),
        (
            Self::RuntimeRootWriteFootprint,
            "runtime_root_write_footprint",
        ),
        (Self::WorkspaceFileListing, "workspace_file_listing"),
        (Self::DefinitionParents, "definition_parents"),
        (Self::PathSyntheticModules, "path_synthetic_modules"),
        (Self::PackageClassDeclarations, "package_class_declarations"),
        (Self::StructuralPostingIndex, "structural_posting_index"),
        (
            Self::RelationalFrontierAnswers,
            "relational_frontier_answers",
        ),
        (
            Self::BoundedIdentifierCandidates,
            "bounded_identifier_candidates",
        ),
        (Self::WorkspaceFileInventory, "workspace_file_inventory"),
        (Self::WorkspaceIgnoreRules, "workspace_ignore_rules"),
        (Self::WorkspaceDirectory, "workspace_directory"),
        (Self::WorkspacePathKind, "workspace_path_kind"),
        (
            Self::WorkspaceAnalyzerLanguages,
            "workspace_analyzer_languages",
        ),
        (
            Self::WorkspaceOverlayMembership,
            "workspace_overlay_membership",
        ),
        (Self::ScalaProjectTypes, "scala_project_types"),
        (Self::ScalaResolvedQuerySeed, "scala_resolved_query_seed"),
        (Self::ScalaExternalIndex, "scala_external_index"),
        (
            Self::ScalaImportableDeclarations,
            "scala_importable_declarations",
        ),
        (Self::ScalaPackageNamespaces, "scala_package_namespaces"),
        (
            Self::ScalaFileDependencyIndex,
            "scala_file_dependency_index",
        ),
        (Self::ScalaLazyHierarchyIndex, "scala_lazy_hierarchy_index"),
        (Self::ScalaTypeRelations, "scala_type_relations"),
        (Self::ScalaDeadCodeUsageEdges, "scala_dead_code_usage_edges"),
        (Self::ScalaReferencingFiles, "scala_referencing_files"),
        (Self::ScalaReverseImportIndex, "scala_reverse_import_index"),
        (
            Self::ScalaSamePackageReferenceIndex,
            "scala_same_package_reference_index",
        ),
        (
            Self::JavaImportedTypeResolution,
            "java_imported_type_resolution",
        ),
    ];

    pub fn stable_label(self) -> &'static str {
        let label = Self::LABELS
            .iter()
            .find_map(|(family, label)| (*family == self).then_some(*label))
            .expect("every workspace fact family has a registered label");
        debug_assert_eq!(
            Self::from_label(label),
            Some(self),
            "workspace fact family labels must round-trip"
        );
        label
    }

    pub fn from_label(label: &str) -> Option<Self> {
        Self::LABELS
            .iter()
            .find_map(|(family, registered)| (*registered == label).then_some(*family))
    }
}

impl Serialize for WorkspaceFactFamily {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.stable_label())
    }
}
impl<'de> Deserialize<'de> for WorkspaceFactFamily {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let label = String::deserialize(deserializer)?;
        Self::from_label(&label).ok_or_else(|| {
            serde::de::Error::custom(format!("unknown workspace fact family {label:?}"))
        })
    }
}

/// A workspace fact's mount-free subject. Names and paths use the same
/// qualified-name and workspace-relative spelling as the authority question.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "subject", rename_all = "snake_case")]
pub enum FactSubject {
    Whole,
    Class {
        class: StableDigest,
    },
    File {
        rel_path: Box<str>,
    },
    Named {
        name: Box<str>,
    },
    NamedMember {
        owner: Box<str>,
        member: Box<str>,
    },
    ClassMember {
        class: StableDigest,
        member: Box<str>,
    },
    NameGroupMember {
        names: Vec<Box<str>>,
        member: Box<str>,
    },
    FileNamedMember {
        rel_path: Box<str>,
        owner: Box<str>,
        member: Box<str>,
        environment: Option<StableDigest>,
    },
}

impl FactSubject {
    /// The caller supplies the authority's canonical qualified-name set.
    pub fn name_group_member(names: Vec<Box<str>>, member: Box<str>) -> Self {
        assert!(
            !names.is_empty() && names.windows(2).all(|pair| pair[0] < pair[1]),
            "workspace fact names must be nonempty, sorted and deduplicated: {names:?}"
        );
        Self::NameGroupMember { names, member }
    }
}

/// The derived-value lookups whose answers are not index probes.
///
/// These are the cross-file channels: an answer can change because a file the
/// reader never mentions gained a caller, an override, or an importer. Each
/// records the canonical digest of its answer, so re-executing the lookup
/// against another workspace and comparing digests is what detects the change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LookupKind {
    /// The exact rendered-name answer of the shared resolver, including its
    /// structured identifier compatibility view and request memo.
    ResolvedName,
    /// The definitions answered by one analyzer delegate or by the composite
    /// workspace lookup.
    Definitions,
    /// The declaration candidates returned by one analyzer's identifier
    /// lookup.
    IdentifierCandidates,
    /// The declaration candidates returned by one analyzer's short-name
    /// lookup.
    ShortNameCandidates,
    /// The exact declaration facts used by a language resolver: the target
    /// declaration identity and the optional declaration that owns it.
    ///
    /// This is deliberately separate from the declaration-index families. A
    /// parent lookup can resolve without hydrating the target's declaring file,
    /// while a structural fallback may read that file, and the answer digest
    /// binds both the target and the resolved parent.
    DeclarationFacts,
    /// The structured signature metadata consumed for one declaration.
    SignatureMetadata,
    /// The callers of one declaration, from the call relation.
    Callers,
    /// The callees of one declaration, from the call relation.
    ///
    /// Separate from [`Self::Usages`] even though both are answers about the
    /// same relation: verification re-executes the funnel a kind names, and
    /// the call relation and the usage finder answer with different digests
    /// over the same subject. A kind that named two funnels could never be
    /// replayed.
    Callees,
    /// The usages of one declaration, from the usage finder.
    Usages,
    /// The files that import one file, from the import topology.
    Importers,
    /// The candidate reference sites of one declaration.
    ReferenceCandidates,
    /// The direct descendants of one type.
    Descendants,
    /// The dispatch targets of one call site.
    Dispatch,
    /// The dispatch targets of one call site addressed relative to its owning
    /// procedure declaration.
    ///
    /// This is distinct from [`Self::Dispatch`], whose source-facing question
    /// is pinned to one exact semantic artifact and absolute source range.
    /// Procedure-local products use this funnel so an edit to a different
    /// declaration in the same file does not change the question.
    ProcedureDispatch,
    /// One procedure summary, by its mount-free identity.
    ProcedureSummary,
    /// A named workspace authority answer.
    WorkspaceFact,
}

impl LookupKind {
    /// The label used in the canonical encoding and in diagnostics.
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::ResolvedName => "resolved_name",
            Self::Definitions => "definitions",
            Self::IdentifierCandidates => "identifier_candidates",
            Self::ShortNameCandidates => "short_name_candidates",
            Self::DeclarationFacts => "declaration_facts",
            Self::SignatureMetadata => "signature_metadata",
            Self::Callers => "callers",
            Self::Callees => "callees",
            Self::Usages => "usages",
            Self::Importers => "importers",
            Self::ReferenceCandidates => "reference_candidates",
            Self::Descendants => "descendants",
            Self::Dispatch => "dispatch",
            Self::ProcedureDispatch => "procedure_dispatch",
            Self::ProcedureSummary => "procedure_summary",
            Self::WorkspaceFact => "workspace_fact",
        }
    }
}

/// One input a request read, named so that another workspace can be asked
/// whether it still denotes the same content.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReadKey {
    /// Any per-file fact read -- declarations, occurrences, structural facts,
    /// syntax, imports, the semantic artifact -- keyed by the language, the
    /// workspace-relative path, and the blob the path resolved to.
    File {
        language: Language,
        rel_path: Box<str>,
        blob: Oid,
    },
    /// A name-keyed lookup served by a per-file fact index.
    Index { family: IndexFamily, key: Box<[u8]> },
    /// One workspace-relative path a module-path or import-specifier probe
    /// stat'ed and did not find.
    ///
    /// The negative half of [`Self::File`]. A resolver that asks "is there a
    /// file at `./helper`" probes a fixed list of candidate paths and, when
    /// none of them exists, returns without reading anything -- so the answer
    /// depends on every one of those paths staying absent, and on nothing
    /// else. Naming each probed path is what lets another workspace be asked
    /// the same question: it has the path, or it does not.
    PathAbsent {
        language: Language,
        rel_path: Box<str>,
    },
    /// A lookup served by an in-memory derived value: the question that was
    /// asked, in a form another workspace can be asked the same question in,
    /// and the canonical digest of the answer it returned.
    Lookup {
        kind: LookupKind,
        question: LookupQuestion,
        digest: StableDigest,
    },
    /// A whole derived artifact consumed as a unit.
    ///
    /// `rel_path` is the file the artifact is derived from, when it has one.
    /// The identity alone cannot be recomputed on another workspace -- a
    /// public fingerprint folds the path, the content, the adapter and the
    /// configuration into 32 bytes and nothing can be read back out -- so a
    /// per-file artifact key carries the locator verification needs to ask the
    /// head what it would derive there now.
    Artifact {
        id: DerivedArtifactId,
        rel_path: Option<Box<str>>,
    },
    /// A whole-language or whole-workspace dependency: the coarse, honest key
    /// for a read that cannot be narrowed to a name or a file.
    ///
    /// `languages` is the exact scope the identity was folded over, sorted, so
    /// another workspace can fold the same scope and compare. A bare digest
    /// could not be recomputed: nothing in it says whether it spans one
    /// language, one ecosystem, or the whole workspace.
    Scope {
        languages: Box<[Language]>,
        identity: WorkspaceContentIdentity,
    },
    /// The active semantic-model set.
    Models(StableDigest),
    /// The policy text itself.
    Policy {
        semantic_hash: StableDigest,
        source: StableDigest,
    },
    /// The analyzer configuration fingerprint.
    Configuration(StableDigest),
    /// The engine epoch.
    Epoch(StableDigest),
}

impl ReadKey {
    /// One per-file fact read of `rel_path`'s `blob`.
    ///
    /// `rel_path` must already be the normalized workspace-relative spelling
    /// (`brokk_bifrost_core::path_utils::rel_path_string`); the caller owns
    /// that conversion because it holds the `ProjectFile` this type refuses to
    /// carry.
    pub fn file(language: Language, rel_path: impl Into<Box<str>>, blob: Oid) -> Self {
        Self::File {
            language,
            rel_path: rel_path.into(),
            blob,
        }
    }

    /// One name-keyed index probe.
    pub fn index(family: IndexFamily, key: impl AsRef<[u8]>) -> Self {
        Self::Index {
            family,
            key: Box::from(key.as_ref()),
        }
    }

    /// One candidate path a probe found nothing at.
    ///
    /// `rel_path` must already be the normalized workspace-relative spelling,
    /// for the same reason [`Self::file`] requires it: the key must compare
    /// equal across two checkouts of the same content.
    pub fn path_absent(language: Language, rel_path: impl Into<Box<str>>) -> Self {
        Self::PathAbsent {
            language,
            rel_path: rel_path.into(),
        }
    }

    /// One derived-value lookup and the digest of the answer it returned.
    pub const fn lookup(kind: LookupKind, question: LookupQuestion, digest: StableDigest) -> Self {
        Self::Lookup {
            kind,
            question,
            digest,
        }
    }

    /// One whole derived artifact, with the file it is derived from.
    pub fn artifact(id: DerivedArtifactId, rel_path: Option<&str>) -> Self {
        Self::Artifact {
            id,
            rel_path: rel_path.map(Box::from),
        }
    }

    /// One semantic artifact and its workspace-relative source path.
    pub fn semantic_artifact(key: &crate::analyzer::semantic::ids::SemanticArtifactKey) -> Self {
        Self::artifact(
            crate::analyzer::semantic::invalidation::DerivedArtifactId::semantic_artifact(
                key.public_fingerprint(),
            ),
            Some(key.path().as_str()),
        )
    }

    /// One whole-scope dependency over exactly `languages`.
    pub fn scope(
        languages: impl IntoIterator<Item = Language>,
        identity: WorkspaceContentIdentity,
    ) -> Self {
        let mut languages = languages.into_iter().collect::<Vec<_>>();
        languages.sort();
        languages.dedup();
        debug_assert!(
            !languages.is_empty(),
            "a scope over no language would compare equal across unrelated workspaces"
        );
        Self::Scope {
            languages: languages.into_boxed_slice(),
            identity,
        }
    }

    /// The stable label of this key's variant.
    pub const fn stable_label(&self) -> &'static str {
        match self {
            Self::File { .. } => "file",
            Self::Index { .. } => "index",
            Self::PathAbsent { .. } => "path_absent",
            Self::Lookup { .. } => "lookup",
            Self::Artifact { .. } => "artifact",
            Self::Scope { .. } => "scope",
            Self::Models(_) => "models",
            Self::Policy { .. } => "policy",
            Self::Configuration(_) => "configuration",
            Self::Epoch(_) => "epoch",
        }
    }

    /// Push this key's canonical encoding into `hasher`.
    ///
    /// Every field is length-delimited and named, so no two keys of different
    /// shapes can encode to the same bytes.
    #[doc(hidden)]
    pub fn push_canonical(&self, hasher: &mut CanonicalHasher) {
        hasher.value(self.stable_label().as_bytes());
        match self {
            Self::File {
                language,
                rel_path,
                blob,
            } => {
                hasher.field("language", language.config_label().as_bytes());
                hasher.field("rel_path", rel_path.as_bytes());
                hasher.field("blob", blob.as_bytes());
            }
            Self::Index { family, key } => {
                hasher.field("family", family.stable_label().as_bytes());
                hasher.field("key", key);
            }
            Self::PathAbsent { language, rel_path } => {
                hasher.field("language", language.config_label().as_bytes());
                hasher.field("rel_path", rel_path.as_bytes());
            }
            Self::Lookup {
                kind,
                question,
                digest,
            } => {
                hasher.field("kind", kind.stable_label().as_bytes());
                question.push_canonical(hasher);
                hasher.field("digest", digest.as_bytes());
            }
            Self::Artifact { id, rel_path } => {
                hasher.field("kind", id.kind().stable_label().as_bytes());
                hasher.field("fingerprint", id.fingerprint().as_bytes());
                hasher.field(
                    "rel_path",
                    rel_path
                        .as_ref()
                        .map_or(b"".as_slice(), |path| path.as_bytes()),
                );
            }
            Self::Scope {
                languages,
                identity,
            } => {
                for language in languages.iter() {
                    hasher.field("language", language.config_label().as_bytes());
                }
                hasher.field("content", identity.digest().as_bytes());
            }
            Self::Models(hash) => hasher.field("models", hash.as_bytes()),
            Self::Policy {
                semantic_hash,
                source,
            } => {
                hasher.field("semantic_hash", semantic_hash.as_bytes());
                hasher.field("source", source.as_bytes());
            }
            Self::Configuration(fingerprint) => {
                hasher.field("configuration", fingerprint.as_bytes())
            }
            Self::Epoch(epoch) => hasher.field("epoch", epoch.as_bytes()),
        }
    }

    /// This key's canonical encoding as a standalone digest, for callers that
    /// need to name one key (a persisted row, a diagnostic) rather than a set.
    pub fn canonical_digest(&self) -> StableDigest {
        let mut hasher = CanonicalHasher::new(READ_KEY_DOMAIN);
        self.push_canonical(&mut hasher);
        StableDigest::from_array(hasher.finish())
    }
}

/// What a derived-value lookup was asked, in a form another workspace can be
/// asked the same thing in.
///
/// A digest of the question would name it but could not re-execute it, and
/// verification against a head workspace is exactly re-execution: resolve the
/// same declaration, the same file, or the same call site there, run the same
/// funnel, and compare the answer digests. So the question is structured, and
/// every field of it is mount-free -- a workspace-relative path, a qualified
/// name, a public artifact fingerprint, a byte range -- because the base half
/// of a `--diff-base` run is analyzed at a temporary root.
///
/// Deliberately not a declaration's byte range or its `DeclarationId`: the
/// same question asked of two checkouts of the same content must be the same
/// question even when the declaration moved within its file.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "question", rename_all = "snake_case")]
pub enum LookupQuestion {
    /// One answer from a named workspace authority.
    WorkspaceFact {
        family: WorkspaceFactFamily,
        language: Language,
        subject: FactSubject,
    },
    /// One name lookup, optionally restricted to one language delegate.
    ///
    /// `None` is the composite question: every language currently mounted,
    /// including languages added in a later workspace revision. `Some` names
    /// one delegate's answer.
    Name {
        language: Option<Language>,
        name: Box<str>,
    },
    /// One declaration, by its file, qualified name, kind, and signature.
    Declaration {
        rel_path: Box<str>,
        fq_name: Box<str>,
        kind: CodeUnitType,
        signature: Option<String>,
    },
    /// One file.
    File { rel_path: Box<str> },
    /// One call site: the file it sits in, the public fingerprint of the
    /// semantic artifact it was resolved against, and its source range.
    ///
    /// The artifact fingerprint is part of the question rather than of the
    /// answer: "dispatch at this range of this artifact" is a different
    /// question from "dispatch at this range of the artifact that file has
    /// now", and a head whose artifact moved has no answer to the first.
    CallSite {
        rel_path: Box<str>,
        artifact: StableDigest,
        site: CallSiteLocator,
    },
    /// One exact procedure-local call site.
    ///
    /// `procedure` is stable declaration lineage. The byte interval is
    /// relative to the owning procedure's start, so a preceding sibling may
    /// move the declaration without changing this question. The ordinal
    /// selects one structured call row among those at that interval.
    ProcedureCallSite {
        rel_path: Box<str>,
        procedure: StableDigest,
        site: ProcedureCallSiteLocator,
    },
    /// One procedure summary, by its mount-free identity.
    Summary { identity: StableDigest },
}

/// Where in its file one call site sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CallSiteLocator {
    pub start_byte: usize,
    pub end_byte: usize,
}

/// Where one call site sits relative to its owning procedure's start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProcedureCallSiteLocator {
    pub start_byte: usize,
    pub end_byte: usize,
    /// The call's position, in call-row order, among the procedure's calls at
    /// exactly this interval. Lowering can give one source call several rows:
    /// a Python `finally` body is lowered once per exit path (#6638).
    pub ordinal: usize,
}

impl LookupQuestion {
    /// The question "what does the workspace answer about this declaration?".
    pub fn declaration(unit: &CodeUnit) -> Self {
        Self::Declaration {
            rel_path: Box::from(rel_path_string(unit.source()).as_str()),
            fq_name: Box::from(unit.fq_name().as_str()),
            kind: unit.kind(),
            signature: unit.signature().map(str::to_owned),
        }
    }

    /// The question "what does the workspace answer about this file?".
    pub fn file(file: &ProjectFile) -> Self {
        Self::File {
            rel_path: Box::from(rel_path_string(file).as_str()),
        }
    }

    /// The question "what does the workspace answer about this call site?".
    ///
    /// `rel_path` is the artifact's own workspace-relative path, which the
    /// semantic artifact key already carries in normalized form; nothing here
    /// re-derives it from a rooted `ProjectFile`.
    pub fn call_site(rel_path: &str, artifact: StableDigest, range: Range) -> Self {
        Self::CallSite {
            rel_path: Box::from(rel_path),
            artifact,
            site: CallSiteLocator {
                start_byte: range.start_byte,
                end_byte: range.end_byte,
            },
        }
    }

    /// The question "what does this procedure-local call site dispatch to?".
    pub fn procedure_call_site(
        rel_path: &str,
        procedure: StableDigest,
        site: ProcedureCallSiteLocator,
    ) -> Self {
        Self::ProcedureCallSite {
            rel_path: Box::from(rel_path),
            procedure,
            site,
        }
    }

    /// The question "what does the workspace answer about this procedure
    /// summary?".
    ///
    /// `identity` is a procedure summary identity's public fingerprint, which
    /// names the procedure, its artifact's content, and the contract the
    /// summary was derived under without folding the workspace mount.
    pub const fn summary(identity: StableDigest) -> Self {
        Self::Summary { identity }
    }

    /// The label used in the canonical encoding and in diagnostics.
    pub const fn stable_label(&self) -> &'static str {
        match self {
            Self::Name { .. } => "name",
            Self::Declaration { .. } => "declaration",
            Self::File { .. } => "file",
            Self::CallSite { .. } => "call_site",
            Self::ProcedureCallSite { .. } => "procedure_call_site",
            Self::Summary { .. } => "summary",
            Self::WorkspaceFact { .. } => "workspace_fact",
        }
    }

    /// The workspace-relative path this question is about, when it names one.
    pub fn rel_path(&self) -> Option<&str> {
        match self {
            Self::Name { .. } | Self::Summary { .. } | Self::WorkspaceFact { .. } => None,
            Self::Declaration { rel_path, .. }
            | Self::File { rel_path }
            | Self::CallSite { rel_path, .. }
            | Self::ProcedureCallSite { rel_path, .. } => Some(rel_path),
        }
    }

    /// Push this question's canonical encoding into `hasher`.
    pub(crate) fn push_canonical(&self, hasher: &mut CanonicalHasher) {
        hasher.field("question", self.stable_label().as_bytes());
        match self {
            Self::Name { language, name } => {
                match language {
                    Some(language) => {
                        hasher.field("language_present", &[1]);
                        hasher.field("language", language.config_label().as_bytes());
                    }
                    None => hasher.field("language_present", &[0]),
                }
                hasher.field("name", name.as_bytes());
            }
            Self::Declaration {
                rel_path,
                fq_name,
                kind,
                signature,
            } => {
                hasher.field("rel_path", rel_path.as_bytes());
                hasher.field("fq_name", fq_name.as_bytes());
                hasher.field("decl_kind", kind.identity_label().as_bytes());
                match signature {
                    Some(signature) => {
                        hasher.field("signature_present", &[1]);
                        hasher.field("signature", signature.as_bytes());
                    }
                    None => hasher.field("signature_present", &[0]),
                }
            }
            Self::File { rel_path } => hasher.field("rel_path", rel_path.as_bytes()),
            Self::CallSite {
                rel_path,
                artifact,
                site,
            } => {
                hasher.field("rel_path", rel_path.as_bytes());
                hasher.field("artifact", artifact.as_bytes());
                hasher.field("start_byte", &(site.start_byte as u64).to_be_bytes());
                hasher.field("end_byte", &(site.end_byte as u64).to_be_bytes());
            }
            Self::ProcedureCallSite {
                rel_path,
                procedure,
                site,
            } => {
                hasher.field("rel_path", rel_path.as_bytes());
                hasher.field("procedure", procedure.as_bytes());
                hasher.field("start_byte", &(site.start_byte as u64).to_be_bytes());
                hasher.field("end_byte", &(site.end_byte as u64).to_be_bytes());
                hasher.field("ordinal", &(site.ordinal as u64).to_be_bytes());
            }
            Self::Summary { identity } => hasher.field("identity", identity.as_bytes()),
            Self::WorkspaceFact {
                family,
                language,
                subject,
            } => {
                hasher.field("family", family.stable_label().as_bytes());
                hasher.field("language", language.config_label().as_bytes());
                match subject {
                    FactSubject::Whole => hasher.field("subject", b"whole"),
                    FactSubject::Class { class } => {
                        hasher.field("subject", b"class");
                        hasher.field("class", class.as_bytes());
                    }
                    FactSubject::File { rel_path } => {
                        hasher.field("subject", b"file");
                        hasher.field("rel_path", rel_path.as_bytes());
                    }
                    FactSubject::Named { name } => {
                        hasher.field("subject", b"named");
                        hasher.field("name", name.as_bytes());
                    }
                    FactSubject::NamedMember { owner, member } => {
                        hasher.field("subject", b"named_member");
                        hasher.field("owner", owner.as_bytes());
                        hasher.field("member", member.as_bytes());
                    }
                    FactSubject::ClassMember { class, member } => {
                        hasher.field("subject", b"class_member");
                        hasher.field("class", class.as_bytes());
                        hasher.field("member", member.as_bytes());
                    }
                    FactSubject::NameGroupMember { names, member } => {
                        // Direct enum construction must satisfy the same invariant.
                        assert!(
                            !names.is_empty() && names.windows(2).all(|pair| pair[0] < pair[1]),
                            "workspace fact names must be nonempty, sorted and deduplicated: {names:?}"
                        );
                        hasher.field("subject", b"name_group_member");
                        hasher.sequence("names", names, |hasher, name| {
                            hasher.field("name", name.as_bytes());
                        });
                        hasher.field("member", member.as_bytes());
                    }
                    FactSubject::FileNamedMember {
                        rel_path,
                        owner,
                        member,
                        environment,
                    } => {
                        hasher.field("subject", b"file_named_member");
                        hasher.field("rel_path", rel_path.as_bytes());
                        hasher.field("owner", owner.as_bytes());
                        hasher.field("member", member.as_bytes());
                        hasher.field("environment_present", &[u8::from(environment.is_some())]);
                        if let Some(environment) = environment {
                            hasher.field("environment", environment.as_bytes());
                        }
                    }
                }
            }
        }
    }
}
