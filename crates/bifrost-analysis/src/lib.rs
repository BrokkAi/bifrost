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

extern crate self as brokk_bifrost_analysis;

#[cfg(any(test, feature = "test-support"))]
#[path = "../../../test-support/inline_project.rs"]
#[doc(hidden)]
pub mod inline_project;

pub mod analyzer;

#[doc(hidden)]
pub mod language_registry;
// `cache_gc` and `path_utils` keep a module here rather than a re-export: each
// has a small tail that needs an `AnalyzerStore` or an `IAnalyzer`, which core
// cannot see. Both re-export their core half at the top of the file.
pub mod cache_gc;

pub mod navigation;
pub mod path_utils;
pub use brokk_bifrost_core::process;
pub use brokk_bifrost_store as store;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
pub mod workspace_document;

pub use brokk_bifrost_core::benchmark_provenance::git_commit;

pub use brokk_bifrost_core::cache_db;
pub use brokk_bifrost_core::cancellation;
pub use brokk_bifrost_core::compact_graph;
pub use brokk_bifrost_core::define_identifier;
pub use brokk_bifrost_core::git_file;
pub use brokk_bifrost_core::gitblob;
pub use brokk_bifrost_core::hash;
pub use brokk_bifrost_core::panic_report;
pub use brokk_bifrost_core::path_normalization;
pub use brokk_bifrost_core::profiling;
pub use brokk_bifrost_core::schema_version;
pub use brokk_bifrost_core::sqlite_template;
pub use brokk_bifrost_core::text_utils;
pub use brokk_bifrost_core::util;

#[doc = " The reader seam's per-method counters (`BIFROST_SEAM_PROFILE`)."]
#[doc = ""]
#[doc = " Re-exported here because the MCP host opens the request boundary and the"]
#[doc = " resolution module itself is crate-private."]
pub use analyzer::resolution::seam_profile;

#[doc = " Reference-seed read repetition per tool call (`BIFROST_SEED_KEY_PROFILE`)."]
#[doc = ""]
#[doc = " Re-exported for the same reason as [`seam_profile`]: the MCP host opens the"]
#[doc = " call boundary and the resolution module itself is crate-private."]
pub use analyzer::resolution::seed_key_profile;

/// Usage APIs and compatibility exports assembled above the language implementations.
pub mod usages {

    pub use crate::analyzer::usages::java_graph::JavaUsageGraphStrategy;

    pub use crate::analyzer::usages::scala_graph::ScalaUsageGraphStrategy;

    pub use crate::analyzer::usages::*;
}
pub use analyzer::AnalyzerConfig;

pub use analyzer::AnalyzerDefinitionLookup;

pub use analyzer::AnalyzerDelegate;

pub use analyzer::BIFROST_IGNORE_FILE_NAME;

pub use analyzer::CapabilityProvider;

pub use analyzer::CloneSmell;

pub use analyzer::CloneSmellWeights;

pub use analyzer::CodeBaseMetrics;

pub use analyzer::CodeUnit;

pub use analyzer::CodeUnitIndex;

pub use analyzer::CodeUnitType;

pub use analyzer::DeclarationInfo;

pub use analyzer::DeclarationKind;

pub use analyzer::DependencyPackActivationOutcome;

pub use analyzer::DependencyPackEcosystem;

pub use analyzer::DependencyPackEcosystemOutcome;

pub use analyzer::DependencyPackWorkspaceContext;

pub use analyzer::DispatchHierarchyExpansion;

pub use analyzer::EmptyAnalyzer;

pub use analyzer::ExceptionHandlingAnalysis;

pub use analyzer::ExceptionHandlingSmell;

pub use analyzer::ExceptionSmellWeights;

pub use analyzer::FileSetProject;

pub use analyzer::FilesystemProject;

pub use analyzer::IAnalyzer;

pub use analyzer::ImportAnalysisProvider;

pub use analyzer::ImportInfo;

pub use analyzer::ImportReachability;

pub use analyzer::IngestedSource;

pub use analyzer::JavaAnalyzer;

pub use analyzer::JvmAnalyzerConfig;

pub use analyzer::JvmDependencyDiscoveryConfig;

pub use analyzer::JvmDependencyDiscoveryMode;

pub use analyzer::JvmExternalArtifact;

pub use analyzer::JvmExternalDependencies;

pub use analyzer::JvmMavenCoordinate;

pub use analyzer::JvmStandardLibraryDiscoveryConfig;

pub use analyzer::KotlinAnalyzer;

pub use analyzer::Language;

pub use analyzer::MultiAnalyzer;

pub use analyzer::MultiRootProject;

pub use analyzer::OverlayProject;

pub use analyzer::ParseCompleteness;

pub use analyzer::ParseError;

pub use analyzer::ParseErrorKind;

pub use analyzer::PhpAnalyzerConfig;

pub use analyzer::PhpDependencyApiEvidence;

pub use analyzer::Project;

pub use analyzer::ProjectCoverage;

pub use analyzer::ProjectFile;

pub use analyzer::PythonSemanticModelWorkspaceContext;

pub use analyzer::Range;

pub use analyzer::RubyAnalyzerConfig;

pub use analyzer::RubyDependencyApiEvidence;

pub use analyzer::RubyGemApiArtifact;

pub use analyzer::ScalaAnalyzer;

pub use analyzer::SourceContent;

pub use analyzer::SourceIngestionError;

pub use analyzer::SourceIngestionKind;

pub use analyzer::SubsetCoverage;

pub use analyzer::TestAssertionAnalysis;

pub use analyzer::TestAssertionSmell;

pub use analyzer::TestAssertionWeights;

pub use analyzer::TestDetectionProvider;

pub use analyzer::TestProject;

pub use analyzer::TreeSitterAnalyzer;

pub use analyzer::TypeAliasProvider;

pub use analyzer::TypeHierarchyProvider;

pub use analyzer::WorkspaceAnalyzer;

pub use analyzer::WorkspaceFileListingCache;

pub use analyzer::collect_workspace_files;

pub use analyzer::ensure_global_rayon_pool;

pub use analyzer::ingest_source_bytes;

pub use cancellation::CancellationToken;

pub use navigation::NavigationOperation;

/// Unstable native-resolution fixtures for the private differential harness.
/// Shipped builds do not expose this module.
#[cfg(any(test, feature = "test-support"))]
pub mod native_resolution_test_support {
    #[test]
    #[ignore = "one-file native smoke run with an external per-file timeout"]
    fn python_environment_native_smoke_file() {
        let root = std::path::PathBuf::from(
            std::env::var_os("BIFROST_PYTHON_ENV_ROOT").expect("selected corpus root"),
        );
        let relative = std::env::var_os("BIFROST_PYTHON_ENV_FILE").expect("selected corpus file");
        let file = brokk_bifrost_core::analyzer::ProjectFile::new(
            &root,
            std::path::PathBuf::from(relative),
        );
        let source = std::fs::read_to_string(file.abs_path()).unwrap();
        let counts = validate_python_native_source(&file, &source);
        println!("native smoke {}: {counts:?}", file.rel_path().display());
    }

    pub use crate::analyzer::jvm::jmod_artifact::test_module_info_class_bytes as jmod_module_info_class_bytes;

    pub use crate::analyzer::resolution::*;

    pub use crate::analyzer::store::python_unit_summaries::PythonSummaryAuthority;
    pub use crate::analyzer::store::python_unit_summaries::PythonSummaryObservation;
    pub use crate::analyzer::store::python_unit_summaries::PythonSummaryProfile;
    pub use crate::analyzer::store::python_unit_summaries::PythonSummaryReceipt;

    pub use crate::analyzer::usages::workspace_graph::SelectedWorkspaceUsageRankingBuildOutcome;
    pub use crate::analyzer::usages::workspace_graph::SelectedWorkspaceUsageRankingGraph;
    pub use crate::analyzer::usages::workspace_graph::build_selected_workspace_usage_ranking_graph;

    pub use crate::analyzer::JavaNativeCallRelations;
    pub use crate::analyzer::JavaNativeRenameProvider;
    pub use crate::analyzer::JavaNativeSelectedInverseProvider;
    pub use crate::analyzer::JavaNativeSelectedReferenceIndex;
    pub use crate::analyzer::JavaNativeUsageStrategy;
    pub use crate::analyzer::JavaSelectedReverseOutcome;
    pub use crate::analyzer::java_native_incoming_calls;
    pub use crate::analyzer::java_native_rename;
    pub use crate::analyzer::java_selected_inverse_for;

    pub use crate::analyzer::NativeAssignmentValueProbe;
    pub use crate::analyzer::NativeTypeProbe;
    pub use crate::analyzer::probe_native_assignment_value;
    pub use crate::analyzer::probe_native_definition;
    pub use crate::analyzer::probe_native_definition_trace;
    pub use crate::analyzer::probe_native_type;

    pub use brokk_bifrost_core::analyzer::model::Language;

    pub use brokk_bifrost_core::analyzer::resolution_facts::BindingProjectionKind;
    pub use brokk_bifrost_core::analyzer::resolution_facts::DeclarationTypeRole;
    pub use brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts;
    pub use brokk_bifrost_core::analyzer::resolution_facts::IntrinsicTypeKind;
    pub use brokk_bifrost_core::analyzer::resolution_facts::ResolutionCallableReceiverOrigin;
    pub use brokk_bifrost_core::analyzer::resolution_facts::ResolutionConstructionRequirementKind;
    pub use brokk_bifrost_core::analyzer::resolution_facts::ResolutionEngineRuleKind;
    pub use brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapFact;
    pub use brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind;
    pub use brokk_bifrost_core::analyzer::resolution_facts::ResolutionImportRouteKind;
    pub use brokk_bifrost_core::analyzer::resolution_facts::ResolutionMemberAccess;
    pub use brokk_bifrost_core::analyzer::resolution_facts::ResolutionMemberKind;
    pub use brokk_bifrost_core::analyzer::resolution_facts::ResolutionMemberQualifierCompatibility;
    pub use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;
    pub use brokk_bifrost_core::analyzer::resolution_facts::ResolutionReferenceEnumerationGapFact;
    pub use brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeFact;
    pub use brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId;
    pub use brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeKind;
    pub use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteFact;
    pub use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId;
    pub use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteKind;
    pub use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSupertypeKind;
    pub use brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeSlotFact;
    pub use brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeSlotId;
    pub use brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeSlotRole;
    pub use brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeTransferKind;

    pub use brokk_bifrost_rust::cargo_routes::rust_static_string_literal;

    /// One fixture identity per label, for a differential suite that needs
    /// distinct identities and no catalog. See `SemanticId::for_test`.
    pub fn fixture_semantic(label: &str) -> SemanticId {
        SemanticId::for_test(label)
    }

    /// See [`fixture_semantic`].
    pub fn fixture_node(label: &str) -> BindingNodeId {
        BindingNodeId::for_test(label)
    }

    /// See [`fixture_semantic`].
    pub fn fixture_path_id(label: &str) -> PartialPathId {
        PartialPathId::for_test(label)
    }

    /// See [`fixture_semantic`].
    pub fn fixture_fragment(label: &[u8]) -> BindingFragmentId {
        BindingFragmentId::for_test(label)
    }

    /// One lowered artifact and the catalog that numbered it, for a
    /// differential suite. The two halves come from one lowering: two
    /// lowerings build two catalogs, and their positions agree only on the
    /// sites.
    pub fn lower_fixture_facts(
        fragment: BindingFragmentId,
        language: Language,
        facts: &FileResolutionFacts,
    ) -> (LoweredResolutionFragment, LoweredTypedFragment) {
        let lowered = lower_for_test(fragment, language, facts);
        (lowered.lexical().clone(), lowered.typed().clone())
    }

    /// Stable complete rows and identity catalogs for producer differentials.
    /// Sorting map entries retains every row while removing hash iteration order.
    pub fn native_lowering_snapshot(
        fragment: BindingFragmentId,
        language: Language,
        facts: &FileResolutionFacts,
    ) -> String {
        let names = PerRequestSharedNames::new();
        let lowered = crate::analyzer::resolution::lower_resolution_facts_for_selection(
            fragment, &names, language, facts,
        );
        let mut out = format!(
            "lexical={:#?}\ntyped={:#?}\ncommon={:#?}\n",
            lowered.lexical(),
            lowered.typed(),
            lowered.common()
        );
        macro_rules! catalog {
            ($label:literal, $rows:expr) => {{
                let mut rows = $rows
                    .iter()
                    .map(|row| format!("{}={row:?}\n", $label))
                    .collect::<Vec<_>>();
                rows.sort_unstable();
                for row in rows {
                    out.push_str(&row);
                }
            }};
        }
        let ids = lowered.identities();
        catalog!("semantic", ids.semantics());
        catalog!("node", ids.nodes());
        catalog!("path", ids.paths());
        catalog!("variable", ids.stack_variables());
        catalog!("scope", ids.source_scope_ordinals());
        catalog!("lookup", ids.lookup_recipes());
        catalog!("precedence", ids.precedence_namespaces());
        catalog!("go_choice", ids.go_spelling_choices());
        catalog!("shared_name", names.digests());
        out
    }

    /// A single corpus file's dormant producer and real lowering. All names and
    /// artifacts are operation-owned; this does not record global fixture names.
    pub fn validate_python_native_source(
        file: &brokk_bifrost_core::analyzer::ProjectFile,
        source: &str,
    ) -> (usize, usize, usize, usize, bool) {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .expect("Python grammar");
        let tree = parser.parse(source, None).expect("Python syntax tree");
        let project =
            brokk_bifrost_core::analyzer::project::TestProject::new(file.root(), Language::Python);
        let production =
            brokk_bifrost_python::declarations::parse_python_file(&project, file, source, &tree);
        assert_eq!(production.resolution_facts, Default::default());
        let bridges = production
            .source_facts
            .as_ref()
            .expect("production source facts");
        assert!(bridges.native_site_occurrences.is_empty());
        assert!(bridges.native_declaration_sources.is_empty());
        drop(production);
        let parsed = brokk_bifrost_python::declarations::parse_python_file_with_native_facts(
            &project, file, source, &tree,
        );
        let facts = &parsed.resolution_facts;
        assert_eq!(
            parsed
                .source_facts
                .as_ref()
                .expect("native source facts")
                .native_site_occurrences
                .len(),
            facts.sites.len()
        );
        for bridge in &facts.definition_units {
            assert!(parsed.contains_declaration(&bridge.unit));
        }
        let names = PerRequestSharedNames::new();
        let lowered = crate::analyzer::resolution::lower_resolution_facts_for_selection(
            fixture_fragment(b"python-corpus"),
            &names,
            Language::Python,
            facts,
        );
        assert!(!lowered.lexical().nodes().is_empty());
        (
            facts.sites.len(),
            facts.python_imports.len(),
            facts.python_guards.len(),
            facts.python_export_operations.len(),
            tree.root_node().has_error(),
        )
    }

    /// Prove that an explicit containment continuation preserves all lowering
    /// outputs and the identity catalog, including common declaration rows.
    pub fn assert_containment_continuation_parity(
        fragment: BindingFragmentId,
        language: Language,
        facts: &FileResolutionFacts,
    ) {
        use brokk_bifrost_core::analyzer::resolution_facts::{
            ResolutionScopeContinuationFact, ResolutionScopeInheritance,
        };
        assert!(facts.scope_continuations.is_empty());
        let before = lower_for_test(fragment, language, facts);
        let mut explicit = facts.clone();
        explicit.scope_continuations = explicit
            .scopes
            .iter()
            .map(|scope| ResolutionScopeContinuationFact {
                scope: scope.id,
                parent: if scope.inheritance == ResolutionScopeInheritance::Lexical {
                    scope.parent
                } else {
                    None
                },
            })
            .collect();
        let after = lower_for_test(fragment, language, &explicit);
        assert_eq!(before.lexical(), after.lexical());
        assert_eq!(before.typed(), after.typed());
        assert_eq!(before.common(), after.common());
        assert_eq!(
            before.identities().semantics(),
            after.identities().semantics()
        );
        assert_eq!(before.identities().nodes(), after.identities().nodes());
        assert_eq!(before.identities().paths(), after.identities().paths());
        assert_eq!(
            before.identities().stack_variables(),
            after.identities().stack_variables()
        );
        assert_eq!(
            before.identities().source_scope_ordinals(),
            after.identities().source_scope_ordinals()
        );
        assert_eq!(
            before.identities().lookup_recipes(),
            after.identities().lookup_recipes()
        );
        assert_eq!(
            before.identities().precedence_namespaces(),
            after.identities().precedence_namespaces()
        );
    }

    /// Parse Python with its coordinated source/native producer for golden gates.
    pub fn parse_python_source(
        file: &brokk_bifrost_core::analyzer::ProjectFile,
        source: &str,
    ) -> brokk_bifrost_core::analyzer::parsed_file::ParsedFile {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .expect("Python grammar");
        let tree = parser.parse(source, None).expect("Python syntax tree");
        let project =
            brokk_bifrost_core::analyzer::project::TestProject::new(file.root(), Language::Python);
        brokk_bifrost_python::declarations::parse_python_file_with_native_facts(
            &project, file, source, &tree,
        )
    }

    /// Probe producer-owned JVM alias coverage through the same bounded
    /// endpoint chain as the persisted alias reader, for private goldens.
    pub fn fixture_jvm_alias_completion(
        language: Language,
        facts: &FileResolutionFacts,
        owner: &[&str],
        name: &str,
        namespace: ResolutionNamespace,
    ) -> ResolutionCompletion {
        let fragment = fixture_fragment(b"jvm-alias-owner-coverage-fixture");
        let lowered = lower_for_test(fragment, language, facts);
        let endpoints =
            crate::analyzer::resolution::alias_lookup_surface_node_identities(owner, namespace)
                .into_iter()
                .filter_map(|identity| lowered.identities().node_for_identity(identity))
                .collect::<Vec<_>>();
        let source = PreloadedFragmentSource::from_lowered_fragments([lowered.lexical().clone()]);
        let lookup = ResolutionLookupSemanticRecipe::new(Language::Java, namespace, name)
            .semantic(fixture_shared_names());
        let mut completion = ResolutionCompletion::Complete;
        for endpoint in endpoints {
            let request = BatchCandidateRequest::new(
                0,
                EndpointSignature::new_scoped(
                    endpoint,
                    StackPattern::closed([PartialScopedSymbol::unscoped(lookup)]),
                    StackPattern::closed([]),
                ),
            );
            let outcome = source
                .visit_forward_candidate_match_pages(
                    &[request],
                    &crate::CancellationToken::new(),
                    &mut |_| unreachable!("alias surfaces have no paths"),
                )
                .expect("fixture alias coverage read");
            completion = completion
                .combine(outcome.unconditional_completion())
                .combine(&outcome.branch_completions()[0]);
        }
        completion
    }

    /// The shared name catalog used by `lower_fixture_facts`, for constructing
    /// a native graph catalog from the same private differential artifacts.
    pub fn fixture_shared_names() -> &'static dyn SharedNameInterner {
        crate::analyzer::resolution::test_shared_names()
    }

    /// Return the exact schema-owned universal root identity for private SQL
    /// differential fixtures without exposing its constructor in shipped APIs.
    pub fn universal_root_binding_node() -> BindingNodeId {
        BindingNodeId::universal_root()
    }

    /// Run the production Java parse walk and return only its target-independent
    /// native-resolution facts for the private differential harness.
    pub fn parse_java_resolution_facts(
        file: &brokk_bifrost_core::analyzer::ProjectFile,
        source: &str,
    ) -> FileResolutionFacts {
        parse_resolution_facts(
            file,
            source,
            tree_sitter_java::LANGUAGE.into(),
            |file, source, tree| {
                brokk_bifrost_jvm::java::declarations::parse_java_file(file, source, tree)
                    .resolution_facts
            },
        )
    }

    /// Run the production Rust parse walk and return only its target-independent
    /// native-resolution facts for the private differential harness.
    pub fn parse_rust_resolution_facts(
        file: &brokk_bifrost_core::analyzer::ProjectFile,
        source: &str,
    ) -> FileResolutionFacts {
        parse_resolution_facts(
            file,
            source,
            tree_sitter_rust::LANGUAGE.into(),
            |file, source, tree| {
                brokk_bifrost_rust::declarations::parse_rust_file(file, source, tree)
                    .resolution_facts
            },
        )
    }

    /// Run the production Go parse walk and return only its target-independent
    /// native-resolution facts for the private differential harness.
    pub fn parse_go_resolution_facts(
        file: &brokk_bifrost_core::analyzer::ProjectFile,
        source: &str,
    ) -> FileResolutionFacts {
        parse_resolution_facts(
            file,
            source,
            tree_sitter_go::LANGUAGE.into(),
            |file, source, tree| {
                brokk_bifrost_go::declarations::parse_go_file(file, source, tree).resolution_facts
            },
        )
    }

    fn parse_resolution_facts(
        file: &brokk_bifrost_core::analyzer::ProjectFile,
        source: &str,
        language: tree_sitter::Language,
        parse: impl FnOnce(
            &brokk_bifrost_core::analyzer::ProjectFile,
            &str,
            &tree_sitter::Tree,
        )
            -> brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts,
    ) -> FileResolutionFacts {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&language)
            .expect("grammar must match the shared tree-sitter runtime");
        let tree = parser
            .parse(source, None)
            .expect("differential fixture must produce a syntax tree");
        parse(file, source, &tree)
    }
}
