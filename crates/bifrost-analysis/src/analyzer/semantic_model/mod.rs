//! Strict authoring and deterministic artifact contracts for semantic-model packs.
//!
//! Compiling a pack does not install or activate it in an analyzer. This module owns only the
//! versioned source model, validation, canonical compilation, and defensive artifact decoding.

mod activation_receipt;
mod artifact;
mod authoring;
mod callable_values;
mod catalog;
mod compiler;
mod conversion;
pub mod csmi;
mod deferred_runtime;
mod dependency;
mod dependency_evidence;
mod identity;
mod model;
mod overlay;
mod producer;
mod python_condition;
mod runtime;
mod runtime_contract_activation;
mod runtime_contracts;
mod source;
mod validate;

pub use activation_receipt::{
    ACTIVATION_RECEIPT_MAX_BYTES, ActivationReceipt, ActivationReceiptInvocation,
    ActivationReceiptStage, ActivationReceiptStageStatus, ActivationReceiptSummary,
    SnapshotBindingStatus,
};
pub(crate) use activation_receipt::{
    ActivationFrame, ActivationOrigin, CandidateDecisionStatus, CandidatePhaseCoverage,
    CandidateQuerySource, FinalSelectionStatus,
};
pub use artifact::{
    ArtifactEncoding, ArtifactError, CompiledAtomicOperation, CompiledClassDecoratorIdentity,
    CompiledClassDecoratorKeyword, CompiledConcurrencyEffect, CompiledCondWaiters,
    CompiledConditionalIndirectWrite, CompiledConditionalResultRefinement, CompiledDeclaredEffect,
    CompiledDeclaredEffectCertainty, CompiledDeclaredEffectTiming, CompiledIndirectWriteTarget,
    CompiledLockCondition, CompiledLockMode, CompiledNormalReturnRefinement,
    CompiledNormalReturnTypeRefinement, CompiledOperationPrecondition, CompiledPackManifest,
    CompiledPayload, CompiledPredicateProofEffect, CompiledProcedureSummary,
    CompiledProcedureTarget, CompiledResultContract, CompiledResultMemberContract,
    CompiledResultPredicate, CompiledResultUseObligation, CompiledSemanticModelPack, CompiledShard,
    CompiledShardArtifact, CompiledShardDescriptor, CompiledSummaryEffect, CompiledSummaryExitKind,
    CompiledSummaryInput, CompiledSummaryLocation, CompiledSummaryLocationKind,
    CompiledSummaryMoveInvalidation, CompiledSummaryOutput, CompiledSummaryPort,
    CompiledSummaryTransfer, CompiledSummaryValuePreservation, CompiledSummaryValueTransfer,
    CompiledSummaryValueTransferKind, CompiledSummaryValueTransferLimitation,
    CompiledSummaryValueTransferLimitationKind, CompiledSummaryValueTransferOperation,
    CompiledSyncMapOperation, CompiledTaskSpawnCondition, DecodeLimits, PayloadKind,
    compiled_flow_claims_agree, decode_manifest, decode_shard, decode_shard_for_manifest,
    decode_validated_shard_for_manifest, validate_manifest_inventory,
};
pub use authoring::*;
pub use callable_values::*;
pub(crate) use catalog::activation_catalog_kind;
pub(crate) use catalog::parse_semantic_pack_activation_source_kind;
pub use catalog::*;
pub use compiler::{
    CompilerOptions, CompressionPolicy, compile_pack, compile_source,
    normalize_callable_values_payload,
};
pub use deferred_runtime::*;
pub(crate) use dependency::activation_selector_for_evidence;
pub(crate) use dependency::missing_dependency_boundary;
pub use dependency::*;
pub use dependency_evidence::*;
pub use identity::{MemberIdentity, TypeIdentity, member_declaration_id, type_declaration_id};
pub use model::*;
pub(crate) use overlay::go_method_signatures_match;
pub(crate) use overlay::symbol_kind_is_callable;
#[cfg(test)]
pub(crate) use overlay::tests::{
    go_callback_field_test_overlay, go_callback_source_field_test_overlay,
    go_external_receiver_test_overlay,
};
pub use overlay::*;
pub(crate) use producer::failed_artifact_production;
pub(crate) use producer::finish_authored_pack_production;
pub(crate) use producer::read_exact_artifact_while;
pub use producer::{
    ArtifactProducerLimits, ArtifactProduction, ArtifactProductionRequest,
    BoundedProducerDiagnostics, ExactArtifact, ExactSourceEntry, ExternalArtifactKind,
    ExternalArtifactPackProducer, ProducerDiagnostic, ProducerDiagnosticSeverity,
    read_exact_artifact, read_exact_source_set,
};

macro_rules! implement_external_artifact_pack_producer {
    ($producer:ty, $produce:ident) => {
        impl $crate::analyzer::semantic_model::ExternalArtifactPackProducer for $producer {
            fn produce_exact_artifact(
                &self,
                request: &$crate::analyzer::semantic_model::ArtifactProductionRequest,
                limits: &$crate::analyzer::semantic_model::ArtifactProducerLimits,
            ) -> $crate::analyzer::semantic_model::ArtifactProduction {
                self.$produce(request, limits, None)
            }

            fn produce_exact_artifact_with_cancellation(
                &self,
                request: &$crate::analyzer::semantic_model::ArtifactProductionRequest,
                limits: &$crate::analyzer::semantic_model::ArtifactProducerLimits,
                cancellation: Option<&$crate::CancellationToken>,
            ) -> $crate::analyzer::semantic_model::ArtifactProduction {
                self.$produce(request, limits, cancellation)
            }
        }
    };
}
pub(crate) use implement_external_artifact_pack_producer;

pub use python_condition::*;
pub(crate) use runtime::acquire_active_semantic_models_with_runtime_artifacts_observed;
pub use runtime::*;
pub use runtime_contract_activation::*;
pub use runtime_contracts::*;
pub use source::SourceFormat;
pub(crate) use validate::is_canonical_relative_path;
pub use validate::{Diagnostic, DiagnosticSeverity};

/// Serialize a value as compact JSON bytes for deterministic ordering and digests.
pub fn compact_json_bytes<T: serde::Serialize + ?Sized>(
    value: &T,
) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(value)
}

/// Returns the current authoring schema as stable, pretty-printed JSON.
pub fn authoring_json_schema() -> String {
    let mut schema = schemars::schema_for!(AuthoredSemanticModelPack);
    let schema_object = schema.ensure_object();
    schema_object.insert(
        "allOf".to_owned(),
        serde_json::json!([
            {
                "if": {
                    "properties": {
                        "schema_version": {"minimum": 2, "maximum": 7}
                    },
                    "required": ["schema_version"]
                },
                "then": {
                    "properties": {
                        "compatibility": {
                            "properties": {"bifrost": {"minLength": 1}},
                            "required": ["bifrost"]
                        }
                    }
                }
            },
            {
                "if": {
                    "properties": {
                        "schema_version": {
                            "minimum": VERSION_INDEPENDENT_COMPATIBILITY_SCHEMA_VERSION,
                            "maximum": SEMANTIC_MODEL_SCHEMA_VERSION
                        }
                    },
                    "required": ["schema_version"]
                },
                "then": {
                    "properties": {
                        "compatibility": {
                            "not": {"required": ["bifrost"]}
                        }
                    }
                }
            }
        ]),
    );
    schema_object.sort_keys();
    for value in schema_object.values_mut() {
        value.sort_all_objects();
    }
    let mut rendered = serde_json::to_string_pretty(&schema).expect("JSON Schema is serializable");
    rendered.push('\n');
    rendered
}

#[cfg(test)]
mod tests {
    use super::{SEMANTIC_MODEL_SCHEMA_VERSION, authoring_json_schema};
    use serde_json::{Value, json};

    #[test]
    fn authoring_schema_exports_ordinary_heap_unchanged_default() {
        let schema = authoring_json_schema();
        assert!(schema.contains("\"ordinary_heap_unchanged\""));
        assert!(schema.contains("\"default\": false"));
        assert!(schema.contains("\"no_concurrency_effects\""));
    }

    #[test]
    fn authoring_schema_conditions_engine_compatibility_on_native_schema() {
        let schema: Value = serde_json::from_str(&authoring_json_schema()).unwrap();
        assert_eq!(
            schema["properties"]["schema_version"]["maximum"],
            SEMANTIC_MODEL_SCHEMA_VERSION
        );
        assert_eq!(
            schema["$defs"]["Compatibility"]["properties"]["bifrost"]["type"],
            "string"
        );
        assert!(
            !schema["$defs"]["Compatibility"]["required"]
                .as_array()
                .is_some_and(|required| required.iter().any(|field| field == "bifrost"))
        );
        assert_eq!(
            schema["allOf"][0]["if"]["properties"]["schema_version"]["maximum"],
            7
        );
        assert_eq!(
            schema["allOf"][0]["then"]["properties"]["compatibility"]["required"],
            json!(["bifrost"])
        );
        assert_eq!(
            schema["allOf"][1]["if"]["properties"]["schema_version"]["minimum"],
            8
        );
        assert_eq!(
            schema["allOf"][1]["then"]["properties"]["compatibility"]["not"]["required"],
            json!(["bifrost"])
        );
    }
}
