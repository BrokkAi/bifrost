pub mod analyzer {
    pub mod java;
    pub mod jvm;
    pub mod kotlin;
    pub mod scala;
    #[cfg(any(test, feature = "test-support"))]
    pub use java::native_call_relations::{JavaNativeCallRelations, java_native_incoming_calls};
    #[cfg(any(test, feature = "test-support"))]
    pub use java::native_rename::{JavaNativeRenameProvider, java_native_rename};
    #[cfg(any(test, feature = "test-support"))]
    pub use java::native_usages::JavaNativeUsageStrategy;
    #[cfg(any(test, feature = "test-support"))]
    pub use java::selected_reverse::{
        JavaNativeSelectedInverseProvider, JavaNativeSelectedReferenceIndex,
        JavaSelectedReverseOutcome, java_selected_inverse_for,
    };
    pub use java::{
        JavaAnalyzer, JavaAnnotationArtifact, JavaAnnotationTypeResolution,
        JavaAnnotationTypeRoute, JavaAnnotationTypeStatus, JavaCallResultUse,
        JavaCallResultUseIndex, JavaCallResultUseOpen, JavaCallResultUseRelationIndex,
        JavaLocalAssignmentConversionProver, JavaLocalAssignmentEvidence,
        java_call_result_use_site, java_plain_string_literal, resolve_java_annotation_type,
    };
    pub use jvm::dependency_evidence::{
        JVM_TOOLCHAIN_ECOSYSTEM, MAVEN_ECOSYSTEM, MavenVersion, MavenVersionRange,
        maven_dependency_version_matches,
    };
    pub use jvm::external::{
        JdkVersion, JvmDependencyPackAdapter, resolve_jvm_semantic_pack_dependencies,
    };
    pub use jvm::java_artifact::JavaJarPackProducer;
    pub use jvm::jdk_artifact::{JdkSourceArchiveLayout, JdkSourceArchivePackProducer};
    pub use jvm::kotlin_artifact::KotlinSourceJarPackProducer;
    pub use jvm::scala_artifact::ScalaSourceJarPackProducer;
    pub use kotlin::KotlinAnalyzer;
    pub use kotlin::kotlin_declared_scalar_types;
    pub use scala::ScalaAnalyzer;
    pub use scala::scala_declared_scalar_types;
    pub mod usages {
        pub mod get_definition {
            pub(crate) use kotlin::{
                kotlin_import_model_outcome, kotlin_package_reference_outcome,
            };
            pub mod java;
            pub mod kotlin;
            pub mod scala;
        }
        pub mod get_type {
            pub(crate) use scala::resolve_scala_type_bounded;
            pub mod java;
            pub mod scala;
        }
        pub mod java_graph;
        pub mod kotlin_graph;
        pub mod scala_graph;
    }
}

pub use analyzer::java::JavaSupport;
pub use analyzer::kotlin::KotlinSupport;
pub use analyzer::scala::ScalaSupport;
pub use analyzer::usages::java_graph::JavaUsageGraphStrategy;
pub use analyzer::usages::kotlin_graph::KotlinUsageGraphStrategy;
pub use analyzer::usages::scala_graph::ScalaUsageGraphStrategy;
pub use analyzer::*;
#[cfg(test)]
#[unsafe(no_mangle)]
fn __brokk_bifrost_language_supports_v1()
-> &'static brokk_bifrost_analysis::analyzer::languages::LanguageTable {
    use brokk_bifrost_analysis::analyzer::languages::{LanguageSupport, LanguageTable};
    static TABLE: std::sync::OnceLock<LanguageTable> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        LanguageTable::partial_for_tests(vec![
            &JavaSupport as &dyn LanguageSupport,
            &KotlinSupport,
            &ScalaSupport,
        ])
    })
}

#[cfg(any(test, feature = "test-support"))]
pub mod native_resolution_test_support {
    pub use crate::analyzer::jvm::jmod_artifact::test_module_info_class_bytes as jmod_module_info_class_bytes;
    /// Test-only fixed owner evidence, deliberately without the scala library.
    /// This is not a product model: it isolates default-provider scope replay.
    pub fn scala_library_scope_fixture(
        analyzer: &dyn brokk_bifrost_analysis::analyzer::IAnalyzer,
    ) -> (
        brokk_bifrost_analysis::analyzer::semantic_model::SemanticPackCatalog,
        String,
    ) {
        use brokk_bifrost_analysis::analyzer::semantic_model::*;
        use brokk_bifrost_semantic::analyzer::semantic_model::{
            compiler::{CompilerOptions, compile_source},
            source::SourceFormat,
        };
        let document = r#"{
            "schema_version": 2, "pack_id": "test.scala-default-scope", "version": "1.0.0",
            "producer": {"name": "bifrost-test", "version": "1.0.0"},
            "language": "scala", "ecosystem": "maven",
            "compatibility": {"bifrost": ">=0.8.0, <1.0.0", "toolchains": []},
            "provenance": {"source": "test:inline #8333", "revision": "scope-replay"},
            "license": "Apache-2.0", "completeness": "complete",
            "safety": {"generated_code_only": false, "review_required": false},
            "shards": [{"id": "decls", "activation": [{
                "module": {"name": "test.scope", "version": ">=1.0.0"}, "targets": ["jvm"], "configurations": []
            }], "payload": {"kind": "declaration_facts", "types": [{
                "id": "type.enumeration", "name": "scala.Enumeration", "type_kind": "class",
                "visibility": "public", "is_abstract": true, "is_sealed": false,
                "has_explicit_type_terms": false, "type_parameters": [], "type_parameter_constraints": [],
                "embedded_types": [], "hierarchy": [{"hierarchy_kind": "extends", "target": {"kind": "named", "name": "scala.AnyRef"}}], "aliases": [], "extension_surfaces": [],
                "jvm_inventory": {"callables_complete": false, "values_complete": false, "types_complete": true, "supertypes_complete": true,
                    "supertypes": [{"hierarchy_kind": "extends", "target": {"kind": "named", "name": "scala.AnyRef"}}], "nested_types": [], "additional_members": []},
                "locator": {"kind": "artifact", "path": "scala/Enumeration.class", "symbol": "scala.Enumeration"}
            }], "members": [], "relations": []}}]
        }"#;
        let pack = compile_source(
            SourceFormat::Json,
            document.as_bytes(),
            &CompilerOptions::default(),
        )
        .unwrap();
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        catalog
            .register_session_pack(
                &pack,
                &SessionPackSource {
                    kind: SessionPackSourceKind::Embedded,
                    source_id: "test-only scope replay declaration".into(),
                },
            )
            .unwrap();
        let request = SemanticModelActivationRequest {
            approximate_standard_libraries: Vec::new(),
            bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
            evidence: vec![SemanticModelActivationEvidence {
                language: "scala".into(),
                ecosystem: "maven".into(),
                package: None,
                module: Some(CatalogCoordinate {
                    name: "test.scope".into(),
                    version: Some(semver::Version::new(1, 0, 0)),
                }),
                toolchain: None,
                target: Some("jvm".into()),
                configuration: None,
                artifact_sha256: None,
            }],
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        };
        let cancellation = brokk_bifrost_analysis::CancellationToken::default();
        let outcome =
            acquire_active_semantic_models(analyzer, &catalog, None, &request, &cancellation);
        assert!(
            matches!(outcome, SemanticModelRuntimeOutcome::Ready { .. }),
            "{outcome:?}"
        );
        let overlay = analyzer.semantic_model_overlay().unwrap();
        let provider = brokk_bifrost_analysis::analyzer::semantic_model::overlay::jvm_external::model_declared_external_owner(
            &overlay, "scala.Enumeration",
        ).unwrap().provider_id.to_string();
        (catalog, provider)
    }
    pub use crate::analyzer::{
        JavaNativeCallRelations, JavaNativeRenameProvider, JavaNativeSelectedInverseProvider,
        JavaNativeSelectedReferenceIndex, JavaNativeUsageStrategy, JavaSelectedReverseOutcome,
        java_native_incoming_calls, java_native_rename, java_selected_inverse_for,
    };
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub use brokk_bifrost_analysis::inline_project;

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod epoch_test_support;

#[cfg(test)]
#[unsafe(no_mangle)]
fn __brokk_bifrost_store_language_supports_v1()
-> &'static brokk_bifrost_analysis::analyzer::store::StoreLanguageTable {
    static TABLE: std::sync::OnceLock<brokk_bifrost_analysis::analyzer::store::StoreLanguageTable> =
        std::sync::OnceLock::new();
    TABLE.get_or_init(|| __brokk_bifrost_language_supports_v1().store_supports())
}

#[cfg(test)]
mod registration_tests;
