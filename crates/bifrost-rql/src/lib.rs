//! RQL syntax, typed IR, planning, execution, and result contracts.

extern crate self as brokk_bifrost_rql;

pub mod query;
pub mod refs;
pub mod sexp;
pub mod structural;

pub use brokk_bifrost_analysis::{path_utils, profiling};
pub mod analyzer {
    #[cfg(any(test, feature = "test-support"))]
    pub use brokk_bifrost_jvm_analysis::analyzer::{
        JavaNativeCallRelations, JavaNativeRenameProvider, JavaNativeSelectedInverseProvider,
        JavaNativeSelectedReferenceIndex, JavaNativeUsageStrategy, JavaSelectedReverseOutcome,
        java_native_incoming_calls, java_native_rename, java_selected_inverse_for,
    };

    pub use brokk_bifrost_jvm_analysis::analyzer::{
        JavaAnalyzer, JavaAnnotationTypeResolution, JavaAnnotationTypeStatus, JavaCallResultUse,
        JavaCallResultUseIndex, JavaCallResultUseOpen, JavaCallResultUseRelationIndex,
        JavaJarPackProducer, JavaLocalAssignmentConversionProver, JavaLocalAssignmentEvidence,
        JdkSourceArchiveLayout, JdkSourceArchivePackProducer, JdkVersion, JvmDependencyPackAdapter,
        KotlinAnalyzer, KotlinSourceJarPackProducer, ScalaAnalyzer, ScalaSourceJarPackProducer,
        java_call_result_use_site, java_plain_string_literal, kotlin_declared_scalar_types,
        resolve_java_annotation_type, resolve_jvm_semantic_pack_dependencies,
        scala_declared_scalar_types,
    };

    pub use brokk_bifrost_analysis::analyzer::semantic;
    pub use brokk_bifrost_analysis::analyzer::*;
    pub use brokk_bifrost_js_ts_analysis::analyzer::js_ts::*;
    pub use brokk_bifrost_js_ts_analysis::{JavascriptAnalyzer, TypescriptAnalyzer};
    pub use brokk_bifrost_jvm_analysis::analyzer::{java, jvm, kotlin, scala};
    pub use brokk_bifrost_rust_analysis::analyzer::{
        RustAnalyzer, RustCallResultUseIndex, RustNativeObligationProof,
        rust_call_is_standard_drop, rust_native_result_obligation,
    };
}
pub use brokk_bifrost_core::{cancellation, hash, text_utils};

pub use refs::{
    MAX_PROTOCOL_NAME_BYTES, MAX_PROTOCOL_NAMESPACE_BYTES, MAX_PROTOCOL_REF_BYTES,
    MAX_TAINT_RESULT_NAME_BYTES, MAX_TAINT_RESULT_NAMESPACE_BYTES, MAX_TAINT_RESULT_REF_BYTES,
    MAX_VALUE_FLOW_PLAN_NAME_BYTES, MAX_VALUE_FLOW_PLAN_NAMESPACE_BYTES,
    MAX_VALUE_FLOW_PLAN_REF_BYTES, ProtocolNameError, ProtocolNamespaceError, ProtocolRef,
    ProtocolRefError, TaintResultNameError, TaintResultNamespaceError, TaintResultRef,
    TaintResultRefError, ValueFlowPlanNameError, ValueFlowPlanNamespaceError, ValueFlowPlanRef,
    ValueFlowPlanRefError,
};
pub use structural::*;
