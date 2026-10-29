pub mod analyzer {
    pub mod go;
    pub use go::GoArtifactCallableTarget;
    pub use go::build_evidence::{
        GoBuildSnapshot, collect_go_build_evidence, go_build_project, go_build_workspace,
        go_evidence_version_cmp,
    };
    #[cfg(any(test, feature = "test-support"))]
    pub use go::native_call_relations::{GoNativeCallRelations, go_native_incoming_calls};
    #[cfg(any(test, feature = "test-support"))]
    pub use go::native_rename::{GoNativeRenameProvider, go_native_rename};
    #[cfg(any(test, feature = "test-support"))]
    pub use go::native_usages::GoNativeUsageStrategy;
    pub use go::package_identity::{
        modeled_go_callable_result_nominal_type, modeled_go_callable_result_pointer_field,
    };
    #[cfg(any(test, feature = "test-support"))]
    pub use go::persist_live_go_sources_for_test;
    #[cfg(any(test, feature = "test-support"))]
    pub use go::selected_reverse::{
        GoNativeSelectedInverseProvider, GoNativeSelectedReferenceIndex, GoSelectedReverseOutcome,
        go_selected_inverse_for,
    };
    pub use go::{
        GO_MODELED_RESULT_BINDING_TYPE_PROOF_MAX_SOURCE_BYTES,
        GO_MODELED_RESULT_BINDING_TYPE_PROOF_MAX_STEPS, GoHttpHandlerDispatch,
        GoHttpHandlerOpenReason, go_http_handler_dispatch,
        go_modeled_result_binding_type_identity_is_exact,
        go_modeled_result_binding_type_identity_proof_work,
        go_native_error_function_value_obligation, go_native_error_result_obligation,
        go_native_obligation_exclusion, reference_assertion_payload_type_is_exact,
        workspace_reference_assertion_accepts_payload,
    };
    pub use go::{
        GoAggregateOperand, GoAggregateSourceBinding, GoAnalyzer,
        GoAnonymousCallableIdentityBindingError, GoBoundAnonymousCallableIdentity,
        GoCallableCaptureBindingError, GoCaptureSlot, GoCaptureSlotPlan,
        GoCatalogAnonymousCallableBindingError, GoDeclaredTypeShape, GoDeclaredTypeUnknown,
        GoDependencyPackAdapter, GoExternalField, GoExternalFieldGap, GoExternalFieldMemory,
        GoExternalFieldQuery, GoFieldReplayRoute, GoFunctionParameterShape, GoFunctionTypeShape,
        GoMaterializedAnonymousCallable, GoModulePackProducer, GoOuterTypeShape, GoPinnedPackage,
        GoReceiverOwnerUnknown, GoReceiverTypeOwner, GoSourceAnchor, GoSourceByteRange,
        GoSourceDeclarationIdentity, GoSourceDeclarationKind, GoSourceIdentityAnalysis,
        GoSourceIdentityGap, GoSourceIdentityGapKind, GoSourceName, GoSourceTypeNode,
        GoStructFieldIdentity, analyze_go_package_source_identities,
        bind_catalog_go_anonymous_callable_target, bind_go_aggregate_operand_source,
        bind_go_anonymous_callable_identity, bind_go_external_field_source,
        go_aggregate_object_is_singleton, go_failure_handler_body_shapes,
        materialize_go_anonymous_callable, observe_go_aggregate_object, resolve_go_external_field,
        resolve_go_semantic_pack_dependencies,
    };
    pub use go::{GoCallResultUseIndex, go_call_result_use};

    pub mod usages {
        pub mod get_definition {
            pub mod go;
        }
    }
}

pub use analyzer::go::*;
#[cfg(test)]
#[unsafe(no_mangle)]
fn __brokk_bifrost_language_supports_v1()
-> &'static brokk_bifrost_analysis::analyzer::languages::LanguageTable {
    use brokk_bifrost_analysis::analyzer::languages::{LanguageSupport, LanguageTable};
    use std::sync::OnceLock;

    static TABLE: OnceLock<LanguageTable> = OnceLock::new();
    TABLE.get_or_init(|| LanguageTable::partial_for_tests(vec![&GoSupport as &dyn LanguageSupport]))
}

#[cfg(test)]
pub use brokk_bifrost_analysis::inline_project;

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

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
