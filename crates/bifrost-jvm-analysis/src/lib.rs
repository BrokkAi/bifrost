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
