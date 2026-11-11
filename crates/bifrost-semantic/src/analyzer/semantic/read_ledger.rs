use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;

use crate::analyzer::semantic::content_identity::WorkspaceContentIdentity;

use crate::analyzer::semantic::invalidation::DerivedArtifactId;

use crate::analyzer::semantic::ids::StableDigest;

use brokk_bifrost_core::analyzer::model::{CodeUnit, CodeUnitType};

use brokk_bifrost_core::analyzer::model::Language;
use brokk_bifrost_core::analyzer::structural::kinds::Role;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::path_utils::rel_path_string;
use git2::Oid;
use serde::{Deserialize, Serialize};

/// A mount-free question about a stored semantic IR publication.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StoredSemanticIrPublicationQuestion {
    pub rel_path: Box<str>,
    pub storage_language: Box<str>,
    pub subject: [u8; 32],
    pub parse_variant: StoredSemanticIrParseVariant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum StoredSemanticIrParseVariant {
    Empty,
    Digest([u8; 32]),
}

/// Cache provenance only for artifacts lowered from source after a refused read.
/// This domain is distinct from every verified built-from question and answer.
pub static REFUSED_PROVENANCE: std::sync::LazyLock<StableDigest> = std::sync::LazyLock::new(|| {
    StableDigest::from_array(
        CanonicalHasher::new(b"bifrost-semantic-artifact:refused-provenance:v1").finish(),
    )
});

impl StoredSemanticIrPublicationQuestion {
    pub fn built_from_digest(&self, answer: &StoredSemanticIrPublicationAnswer) -> StableDigest {
        let mut hasher = CanonicalHasher::new(b"bifrost-semantic-artifact:built-from:v1");
        LookupQuestion::StoredSemanticIrPublication(self.clone()).push_canonical(&mut hasher);
        hasher.field(
            "answer_digest",
            answer.clone().canonical_digest().as_bytes(),
        );
        StableDigest::from_array(hasher.finish())
    }

    pub fn new(
        rel_path: Box<str>,
        storage_language: Box<str>,
        subject: [u8; 32],
        variant: brokk_bifrost_core::gitblob::ParseVariant,
    ) -> Self {
        let parse_variant = match variant {
            brokk_bifrost_core::gitblob::ParseVariant::Empty => StoredSemanticIrParseVariant::Empty,
            brokk_bifrost_core::gitblob::ParseVariant::Digest(digest) => {
                StoredSemanticIrParseVariant::Digest(digest)
            }
        };
        Self {
            rel_path,
            storage_language,
            subject,
            parse_variant,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredSemanticIrPublicationAnswer {
    NoHead,
    StaleEpoch,
    ContentMismatch,
    Present {
        active_epoch: Box<str>,
        row_digest: [u8; 32],
    },
}

impl StoredSemanticIrPublicationAnswer {
    pub fn canonical_digest(self) -> StableDigest {
        let mut hasher = CanonicalHasher::new(b"bifrost-stored-semantic-ir-publication:answer:v1");
        match self {
            Self::NoHead => hasher.field("answer", b"no_head"),
            Self::StaleEpoch => hasher.field("answer", b"stale_epoch"),
            Self::ContentMismatch => hasher.field("answer", b"content_mismatch"),
            Self::Present {
                active_epoch,
                row_digest,
            } => {
                hasher.field("answer", b"present");
                hasher.field("active_epoch", active_epoch.as_bytes());
                hasher.field("row_digest", &row_digest);
            }
        }
        StableDigest::from_array(hasher.finish())
    }
}

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
    GoHierarchySeeks,
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
    RubySingletonMemberMutation,
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
    JvmSelectedRootPresence,
    JvmExternalGaps,
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
        (Self::GoHierarchySeeks, "go_hierarchy_seeks"),
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
        (
            Self::RubySingletonMemberMutation,
            "ruby_singleton_member_mutation",
        ),
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
        (Self::JvmSelectedRootPresence, "jvm_selected_root_presence"),
        (Self::JvmExternalGaps, "jvm_external_gaps"),
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
    /// Certified composite answer to a definition probe.
    CertifiedDefinitionAnswer,
    StoredSemanticIrPublication,
    /// A registered dependency-tracked derivation.
    Derivation(crate::analyzer::semantic::derivation::DerivationKindId),
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
    /// Selected bound impl endpoints keyed by the placed subject declaration.
    RustTraitsImplementedByInventory,
    /// Live published alias blobs mentioning one Rust spelling.
    RustAliasBlobInventory,
    /// Live published macro expansion candidates for one spelling.
    RustMacroExpansionInventory,
    /// Selected bound impl endpoints keyed by the placed trait declaration.
    RustBoundTraitImplInventory,
    /// Selected live unresolved impls naming one Rust trait spelling.
    RustUnresolvedTraitImplInventory,
    /// Selected live placements whose imports can name one Rust component.
    RustModuleImportCandidateInventory,
    /// Selected live blobs and context masks for one Rust identifier.
    RustIdentifierOccurrenceInventory,
    /// The exact declaration facts used by a language resolver: the target
    /// declaration identity and the optional declaration that owns it.
    ///
    /// This is deliberately separate from the declaration-index families. A
    /// parent lookup can resolve without hydrating the target's declaring file,
    /// while a structural fallback may read that file, and the answer digest
    /// binds both the target and the resolved parent.
    DeclarationFacts,
    /// The full set of parser declarations matching a declaration question's
    /// rendered name, kind and signature. Membership within that set is exact.
    DeclarationCandidates,
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
    /// Handle-keyed dispatch through the same stable procedure/rank address
    /// as source-selected dispatch. Source selection separately records its
    /// whole-artifact input, including an empty or partial selection.
    ProcedureDispatch,
    /// One procedure summary, by its mount-free identity.
    ProcedureSummary,
    /// A named workspace authority answer.
    WorkspaceFact,
    /// Exact-name structural posting inventory across one selected provider.
    StructuralNameInventory,
    StructuralRoleNameInventory,
    /// Recovered-file inventory across one selected structural provider.
    StructuralRecoveredInventory,
    /// A selected Rust crate's closed census of impl subjects for one local ADT.
    RustCopyAbsence,
    /// The external (dependency) semantic-pack inputs one request selected,
    /// recorded as the digest of the selection question and the digest of the
    /// answer it produced.
    ExternalSelection,
}

/// Persisted derivation labels and the exact question shape admitted for each.
#[derive(Debug, Clone, Copy)]
pub struct PersistedDerivationFamily {
    pub id: crate::analyzer::semantic::derivation::DerivationKindId,
    pub language: bool,
    pub subject: bool,
    pub rel_path: bool,
    pub name: bool,
    /// The kind is computed only on a lent, in-memory operation, so no
    /// persisted read set may hold its lookup: replay has no operation to
    /// recompute it on. Only the codec table in [`Self::of`] sets this; a
    /// kind's own `QUESTION_SHAPE` leaves it false.
    pub memory_only: bool,
}

impl PersistedDerivationFamily {
    pub const fn new(
        id: crate::analyzer::semantic::derivation::DerivationKindId,
        language: bool,
        subject: bool,
        rel_path: bool,
        name: bool,
    ) -> Self {
        Self {
            id,
            language,
            subject,
            rel_path,
            name,
            memory_only: false,
        }
    }
    /// The codec entry for a registered derivation label. Each entry states
    /// its question shape and whether the kind is memory-only, so a newly
    /// registered kind cannot be persisted without an explicit decision.
    pub fn of(label: &str) -> Option<Self> {
        let (id, language, subject, rel_path, name, memory_only) = match label {
            "derivation:unit_summary:v1" => (
                "derivation:unit_summary:v1",
                true,
                true,
                false,
                false,
                false,
            ),
            "derivation:rust_unit_set:v1" => (
                "derivation:rust_unit_set:v1",
                true,
                false,
                false,
                false,
                false,
            ),
            "derivation:rust_file_units:v1" => (
                "derivation:rust_file_units:v1",
                true,
                false,
                true,
                false,
                false,
            ),
            "derivation:rust_broad_file_units:v1" => (
                "derivation:rust_broad_file_units:v1",
                true,
                false,
                true,
                false,
                false,
            ),
            "derivation:rust_unit_routes:v1" => (
                "derivation:rust_unit_routes:v1",
                true,
                true,
                false,
                false,
                false,
            ),
            "derivation:rust_route_directory:v1" => (
                "derivation:rust_route_directory:v1",
                false,
                false,
                false,
                false,
                false,
            ),
            "derivation:rust_route_index:v1" => (
                "derivation:rust_route_index:v1",
                false,
                false,
                false,
                false,
                false,
            ),
            "derivation:rust_selected_units_known:v1" => (
                "derivation:rust_selected_units_known:v1",
                true,
                false,
                false,
                false,
                false,
            ),
            "derivation:rust_unit_dependency_identities:v1" => (
                "derivation:rust_unit_dependency_identities:v1",
                true,
                true,
                false,
                false,
                false,
            ),
            "derivation:rust_unit_naming:v1" => (
                "derivation:rust_unit_naming:v1",
                true,
                true,
                false,
                false,
                false,
            ),
            "derivation:rust_unit_inputs:v1" => (
                "derivation:rust_unit_inputs:v1",
                true,
                true,
                false,
                false,
                false,
            ),
            "derivation:rust_unit_dependents:v1" => (
                "derivation:rust_unit_dependents:v1",
                true,
                true,
                false,
                false,
                false,
            ),
            "derivation:rust_package_units:v1" => (
                "derivation:rust_package_units:v1",
                true,
                false,
                false,
                true,
                false,
            ),
            "derivation:rust_target_reachability:v2" => (
                "derivation:rust_target_reachability:v2",
                true,
                true,
                false,
                false,
                false,
            ),
            "derivation:rust_crate_name_units:v2" => (
                "derivation:rust_crate_name_units:v2",
                true,
                false,
                false,
                true,
                false,
            ),
            "derivation:rust_unit_package_rows:v1" => (
                "derivation:rust_unit_package_rows:v1",
                true,
                true,
                false,
                false,
                false,
            ),
            // Retired by #10949; kept only so old stored read sets decode.
            // Never register this label again: use a new label or version.
            // Delete only after the store file version suffix moves past every
            // store that could hold these read sets.
            "derivation:rust_selection_content:v1" => (
                "derivation:rust_selection_content:v1",
                true,
                false,
                false,
                false,
                false,
            ),
            // Retired by #10949; kept only so old stored read sets decode.
            // Never register this label again: use a new label or version.
            // Delete only after the store file version suffix moves past every
            // store that could hold these read sets.
            "derivation:rust_selection_content:v2" => (
                "derivation:rust_selection_content:v2",
                true,
                false,
                false,
                false,
                false,
            ),
            // Retired by #10949; kept only so old stored read sets decode.
            // Never register this label again: use a new label or version.
            // Delete only after the store file version suffix moves past every
            // store that could hold these read sets.
            "derivation:rust_forward_scope_witness:v1" => (
                "derivation:rust_forward_scope_witness:v1",
                true,
                true,
                true,
                false,
                false,
            ),
            // Retired by #10949; kept only so old stored read sets decode.
            // Never register this label again: use a new label or version.
            // Delete only after the store file version suffix moves past every
            // store that could hold these read sets.
            "derivation:rust_call_site_resolution:v1" => (
                "derivation:rust_call_site_resolution:v1",
                true,
                true,
                true,
                true,
                true,
            ),
            _ => return None,
        };
        Some(Self {
            id: crate::analyzer::semantic::derivation::DerivationKindId(id),
            language,
            subject,
            rel_path,
            name,
            memory_only,
        })
    }

    pub fn admits(
        self,
        question: &crate::analyzer::semantic::derivation::DerivationQuestion,
    ) -> bool {
        question.language.is_some() == self.language
            && question.subject.is_some() == self.subject
            && question.rel_path.is_some() == self.rel_path
            && question.name.is_some() == self.name
    }
}

impl LookupKind {
    /// The label used in the canonical encoding and in diagnostics.
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::CertifiedDefinitionAnswer => "certified_definition_answer",
            Self::StoredSemanticIrPublication => "stored_semantic_ir_publication",
            Self::Derivation(id) => id.0,
            Self::ResolvedName => "resolved_name",
            Self::Definitions => "definitions",
            Self::IdentifierCandidates => "identifier_candidates",
            Self::ShortNameCandidates => "short_name_candidates",
            Self::RustTraitsImplementedByInventory => "rust_traits_implemented_by_inventory",
            Self::RustAliasBlobInventory => "rust_alias_blob_inventory",
            Self::RustMacroExpansionInventory => "rust_macro_expansion_inventory",
            Self::RustBoundTraitImplInventory => "rust_bound_trait_impl_inventory",
            Self::RustUnresolvedTraitImplInventory => "rust_unresolved_trait_impl_inventory",
            Self::RustModuleImportCandidateInventory => "rust_module_import_candidate_inventory",
            Self::RustIdentifierOccurrenceInventory => "rust_identifier_occurrence_inventory",
            Self::DeclarationFacts => "declaration_facts",
            Self::DeclarationCandidates => "declaration_candidates",
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
            Self::StructuralNameInventory => "structural_name_inventory",
            Self::StructuralRoleNameInventory => "structural_role_name_inventory",
            Self::StructuralRecoveredInventory => "structural_recovered_inventory",
            Self::RustCopyAbsence => "rust_copy_absence",
            Self::ExternalSelection => "external_selection",
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
        parse_variant: brokk_bifrost_core::gitblob::ParseVariant,
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
    /// Whether a persisted read set may hold this key.
    ///
    /// The one predicate every publisher of a read set to disk applies. A
    /// derivation lookup is persistable only when its kind is registered in the
    /// persisted codec and is not memory-only: replay recomputes a persisted
    /// lookup from a stored inventory, and a kind computed on a lent in-memory
    /// operation (or one the codec does not know) has nothing to recompute on.
    pub fn is_persistable(&self) -> bool {
        match self {
            Self::Lookup {
                kind: LookupKind::Derivation(id),
                ..
            } => PersistedDerivationFamily::of(id.0).is_some_and(|family| !family.memory_only),
            _ => true,
        }
    }

    /// One per-file fact read of `rel_path`'s `blob`.
    ///
    /// `rel_path` must already be the normalized workspace-relative spelling
    /// (`brokk_bifrost_core::path_utils::rel_path_string`); the caller owns
    /// that conversion because it holds the `ProjectFile` this type refuses to
    /// carry.
    pub fn file(
        language: Language,
        rel_path: impl Into<Box<str>>,
        blob: Oid,
        parse_variant: brokk_bifrost_core::gitblob::ParseVariant,
    ) -> Self {
        Self::File {
            language,
            rel_path: rel_path.into(),
            blob,
            parse_variant,
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
                parse_variant,
            } => {
                hasher.field("language", language.config_label().as_bytes());
                hasher.field("rel_path", rel_path.as_bytes());
                hasher.field("blob", blob.as_bytes());
                if let Some(variant) = parse_variant.file_read_key_field() {
                    hasher.field("parse_variant", variant);
                }
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
    /// One Rust declaration placed in a selected workspace file.
    RustPlacedDeclaration {
        blob: [u8; 20],
        declaration: u32,
        rel_path: Box<str>,
    },
    /// A definition probe over exactly these language delegates. The normalized
    /// form is already normalized and must be looked up without another pass.
    CertifiedDefinition {
        kind: CertifiedDefinitionKind,
        name: Box<str>,
        delegates: Vec<Language>,
        normalization_version: Option<u32>,
    },
    StoredSemanticIrPublication(StoredSemanticIrPublicationQuestion),
    /// Mount-free key of a registered derivation.
    Derivation(crate::analyzer::semantic::derivation::DerivationQuestion),
    /// The selected crate, target declaration and authorities for Copy absence.
    RustCopyAbsence {
        owning_unit: StableDigest,
        target_unit: StableDigest,
        module_path: Box<str>,
        target_identity_digest: StableDigest,
        census_version: u32,
        config_digest: StableDigest,
        producer_digest: StableDigest,
    },
    /// Exact-name posting inventory under one provider's selection authority.
    StructuralName {
        language: Language,
        name: Box<str>,
        authority: StableDigest,
    },
    StructuralRoleName {
        language: Language,
        role: Role,
        name: Box<str>,
        keyword: bool,
        authority: StableDigest,
    },
    /// Recovered-file inventory under one provider's selection authority.
    StructuralRecovered {
        language: Language,
        authority: StableDigest,
    },
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
    File {
        rel_path: Box<str>,
    },
    /// One call addressed by stable procedure lineage and source-order rank.
    CallSite {
        rel_path: Box<str>,
        procedure: StableDigest,
        site: CallSiteLocator,
    },
    /// One procedure summary, by its mount-free identity.
    Summary {
        identity: StableDigest,
    },
    /// The external-input selection one request made, by the digest of the
    /// selection question. The answer digest rides in the key's `digest`.
    ExternalSelection {
        question_digest: [u8; 32],
    },
}

/// The three definition questions admitted by protocol certificates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CertifiedDefinitionKind {
    Exact,
    NormalizedTail,
    Identifier,
}

/// Increment when the normalized-tail key or matching rule changes.
pub const DEFINITION_NORMALIZED_TAIL_VERSION: u32 = 1;

/// A call's rank among its enclosing procedure's calls in source order.
/// Equal source spans retain semantic call-row order as a tie breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CallSiteLocator {
    pub ordinal: usize,
}

impl LookupQuestion {
    /// Construct a canonical composite definition question.
    pub fn certified_definition(
        kind: CertifiedDefinitionKind,
        name: impl Into<Box<str>>,
        delegates: impl IntoIterator<Item = Language>,
    ) -> Self {
        let mut delegates: Vec<_> = delegates.into_iter().collect();
        delegates.sort();
        delegates.dedup();
        assert!(
            !delegates.is_empty(),
            "a certified definition needs a delegate"
        );
        Self::CertifiedDefinition {
            kind,
            name: name.into(),
            delegates,
            normalization_version: (kind == CertifiedDefinitionKind::NormalizedTail)
                .then_some(DEFINITION_NORMALIZED_TAIL_VERSION),
        }
    }

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

    /// One stable procedure-local call question.
    pub fn procedure_call_site(
        rel_path: &str,
        procedure: StableDigest,
        site: CallSiteLocator,
    ) -> Self {
        Self::CallSite {
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
            Self::CertifiedDefinition { .. } => "certified_definition",
            Self::StoredSemanticIrPublication(..) => "stored_semantic_ir_publication",
            Self::Derivation(_) => "derivation",
            Self::Name { .. } => "name",
            Self::RustPlacedDeclaration { .. } => "rust_placed_declaration",
            Self::Declaration { .. } => "declaration",
            Self::File { .. } => "file",
            Self::CallSite { .. } => "call_site",
            Self::Summary { .. } => "summary",
            Self::WorkspaceFact { .. } => "workspace_fact",
            Self::StructuralName { .. } => "structural_name",
            Self::StructuralRoleName { .. } => "structural_role_name",
            Self::StructuralRecovered { .. } => "structural_recovered",
            Self::RustCopyAbsence { .. } => "rust_copy_absence",
            Self::ExternalSelection { .. } => "external_selection",
        }
    }

    /// The workspace-relative path this question is about, when it names one.
    pub fn rel_path(&self) -> Option<&str> {
        match self {
            Self::StoredSemanticIrPublication(question) => Some(&question.rel_path),
            Self::CertifiedDefinition { .. } => None,
            Self::Derivation(question) => question.rel_path.as_deref(),
            Self::Name { .. }
            | Self::Summary { .. }
            | Self::WorkspaceFact { .. }
            | Self::StructuralName { .. }
            | Self::StructuralRoleName { .. }
            | Self::StructuralRecovered { .. } => None,
            Self::RustCopyAbsence { .. } | Self::ExternalSelection { .. } => None,
            Self::RustPlacedDeclaration { rel_path, .. }
            | Self::Declaration { rel_path, .. }
            | Self::File { rel_path }
            | Self::CallSite { rel_path, .. } => Some(rel_path),
        }
    }

    /// Push this question's canonical encoding into `hasher`.
    pub(crate) fn push_canonical(&self, hasher: &mut CanonicalHasher) {
        hasher.field("question", self.stable_label().as_bytes());
        match self {
            Self::RustPlacedDeclaration {
                blob,
                declaration,
                rel_path,
            } => {
                hasher.field("blob", blob);
                hasher.field("declaration", &declaration.to_be_bytes());
                hasher.field("rel_path", rel_path.as_bytes());
            }
            Self::CertifiedDefinition {
                kind,
                name,
                delegates,
                normalization_version,
            } => {
                let kind = match kind {
                    CertifiedDefinitionKind::Exact => "exact",
                    CertifiedDefinitionKind::NormalizedTail => "normalized_tail",
                    CertifiedDefinitionKind::Identifier => "identifier",
                };
                hasher.field("kind", kind.as_bytes());
                hasher.field("name", name.as_bytes());
                for delegate in delegates {
                    hasher.field("delegate", delegate.config_label().as_bytes());
                }
                hasher.field(
                    "normalization_version",
                    &normalization_version.unwrap_or(0).to_be_bytes(),
                );
            }
            Self::StoredSemanticIrPublication(question) => {
                hasher.field("rel_path", question.rel_path.as_bytes());
                hasher.field("storage_language", question.storage_language.as_bytes());
                hasher.field("subject", &question.subject);
                match question.parse_variant {
                    StoredSemanticIrParseVariant::Empty => {
                        hasher.field("parse_variant_kind", b"empty")
                    }
                    StoredSemanticIrParseVariant::Digest(digest) => {
                        hasher.field("parse_variant_kind", b"digest");
                        hasher.field("parse_variant_digest", &digest);
                    }
                }
            }
            Self::Derivation(question) => {
                if let Some(language) = question.language {
                    hasher.field("language", language.config_label().as_bytes());
                }
                if let Some(subject) = question.subject {
                    hasher.field("subject", &subject);
                }
                if let Some(path) = &question.rel_path {
                    hasher.field("rel_path", path.as_bytes());
                }
                if let Some(name) = &question.name {
                    hasher.field("name", name.as_bytes());
                }
            }
            Self::RustCopyAbsence {
                owning_unit,
                target_unit,
                module_path,
                target_identity_digest,
                census_version,
                config_digest,
                producer_digest,
            } => {
                hasher.field("owning_unit", owning_unit.as_bytes());
                hasher.field("target_unit", target_unit.as_bytes());
                hasher.field("module_path", module_path.as_bytes());
                hasher.field("target_identity_digest", target_identity_digest.as_bytes());
                hasher.field("census_version", &census_version.to_be_bytes());
                hasher.field("config_digest", config_digest.as_bytes());
                hasher.field("producer_digest", producer_digest.as_bytes());
            }
            Self::StructuralName {
                language,
                name,
                authority,
            } => {
                hasher.field("language", language.config_label().as_bytes());
                hasher.field("name", name.as_bytes());
                hasher.field("authority", authority.as_bytes());
            }
            Self::StructuralRoleName {
                language,
                role,
                name,
                keyword,
                authority,
            } => {
                hasher.field("language", language.config_label().as_bytes());
                hasher.field("role", role.label().as_bytes());
                hasher.field("name", name.as_bytes());
                hasher.field("keyword", &[*keyword as u8]);
                hasher.field("authority", authority.as_bytes());
            }
            Self::StructuralRecovered {
                language,
                authority,
            } => {
                hasher.field("language", language.config_label().as_bytes());
                hasher.field("authority", authority.as_bytes());
            }
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
                procedure,
                site,
            } => {
                hasher.field("rel_path", rel_path.as_bytes());
                hasher.field("procedure", procedure.as_bytes());
                hasher.field("ordinal", &(site.ordinal as u64).to_be_bytes());
            }
            Self::Summary { identity } => hasher.field("identity", identity.as_bytes()),
            Self::ExternalSelection { question_digest } => {
                hasher.field("question_digest", question_digest)
            }
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

// The derivation budget owns the cloned keys in its read vector. Count the
// vector's inline slots at the entry and the allocations here.
impl brokk_bifrost_core::retention_budget::RetainedBytes for ReadKey {
    fn retained_bytes(&self) -> usize {
        use std::mem::size_of;
        let owned = match self {
            Self::File { rel_path, .. } | Self::PathAbsent { rel_path, .. } => rel_path.len(),
            Self::Index { key, .. } => key.len(),
            Self::Lookup { question, .. } => match question {
                LookupQuestion::CertifiedDefinition {
                    name, delegates, ..
                } => name.len() + delegates.capacity() * size_of::<Language>(),
                LookupQuestion::StoredSemanticIrPublication(q) => {
                    q.rel_path.len() + q.storage_language.len()
                }
                LookupQuestion::Derivation(q) => {
                    q.rel_path.as_ref().map_or(0, |p| p.len())
                        + q.name.as_ref().map_or(0, |n| n.len())
                }
                LookupQuestion::RustCopyAbsence { module_path, .. } => module_path.len(),
                LookupQuestion::StructuralName { name, .. }
                | LookupQuestion::StructuralRoleName { name, .. }
                | LookupQuestion::Name { name, .. } => name.len(),
                LookupQuestion::StructuralRecovered { .. }
                | LookupQuestion::Summary { .. }
                | LookupQuestion::ExternalSelection { .. } => 0,
                LookupQuestion::Declaration {
                    rel_path,
                    fq_name,
                    signature,
                    ..
                } => {
                    rel_path.len() + fq_name.len() + signature.as_ref().map_or(0, String::capacity)
                }
                LookupQuestion::RustPlacedDeclaration { rel_path, .. }
                | LookupQuestion::File { rel_path }
                | LookupQuestion::CallSite { rel_path, .. } => rel_path.len(),
                LookupQuestion::WorkspaceFact { subject, .. } => match subject {
                    FactSubject::Whole | FactSubject::Class { .. } => 0,
                    FactSubject::File { rel_path } => rel_path.len(),
                    FactSubject::Named { name } => name.len(),
                    FactSubject::NamedMember { owner, member } => owner.len() + member.len(),
                    FactSubject::ClassMember { member, .. } => member.len(),
                    FactSubject::NameGroupMember { names, member } => {
                        names.capacity() * size_of::<Box<str>>()
                            + names.iter().map(|name| name.len()).sum::<usize>()
                            + member.len()
                    }
                    FactSubject::FileNamedMember {
                        rel_path,
                        owner,
                        member,
                        ..
                    } => rel_path.len() + owner.len() + member.len(),
                },
            },
            Self::Artifact { rel_path, .. } => rel_path.as_ref().map_or(0, |p| p.len()),
            Self::Scope { languages, .. } => languages.len() * size_of::<Language>(),
            Self::Models(_) | Self::Policy { .. } | Self::Configuration(_) | Self::Epoch(_) => 0,
        };
        size_of::<Self>().saturating_add(owned)
    }
}
