//! Strict authoring and deterministic artifact contracts for semantic-model packs.
//!
//! Compiling a pack does not install or activate it in an analyzer. This module owns only the
//! versioned source model, validation, canonical compilation, and defensive artifact decoding.

mod artifact;
mod authoring;
mod catalog;
mod compiler;
pub mod csmi;
mod deferred_runtime;
mod dependency;
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
    CompiledSummaryMoveInvalidation, CompiledSummaryOutput, CompiledSummaryTransfer,
    CompiledSummaryValuePreservation, CompiledSummaryValueTransfer,
    CompiledSummaryValueTransferKind, CompiledSummaryValueTransferLimitation,
    CompiledSummaryValueTransferLimitationKind, CompiledSummaryValueTransferOperation,
    CompiledSyncMapOperation, CompiledTaskSpawnCondition, DecodeLimits, PayloadKind,
    decode_manifest, decode_shard, decode_shard_for_manifest, decode_validated_shard_for_manifest,
    validate_manifest_inventory,
};
pub use authoring::*;
pub use catalog::*;
pub use compiler::{CompilerOptions, CompressionPolicy, compile_pack, compile_source};
pub use deferred_runtime::*;
pub use dependency::*;
pub use identity::{MemberIdentity, TypeIdentity, member_declaration_id, type_declaration_id};
pub use model::*;
#[cfg(test)]
pub(crate) use overlay::tests::go_external_receiver_test_overlay;
pub use overlay::*;
pub(crate) use producer::read_exact_artifact_while;
pub use producer::{
    ArtifactProducerLimits, ArtifactProduction, ArtifactProductionRequest,
    BoundedProducerDiagnostics, ExactArtifact, ExactSourceEntry, ExternalArtifactKind,
    ExternalArtifactPackProducer, ProducerDiagnostic, ProducerDiagnosticSeverity,
    read_exact_artifact, read_exact_source_set,
};
pub use python_condition::*;
pub use runtime::*;
pub use runtime_contract_activation::*;
pub use runtime_contracts::*;
pub use source::SourceFormat;
pub(crate) use validate::is_canonical_relative_path;
pub use validate::{Diagnostic, DiagnosticSeverity};

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
                        "schema_version": {"const": 8}
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
    use super::authoring_json_schema;
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
        assert_eq!(schema["properties"]["schema_version"]["maximum"], 8);
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
            schema["allOf"][1]["if"]["properties"]["schema_version"]["const"],
            8
        );
        assert_eq!(
            schema["allOf"][1]["then"]["properties"]["compatibility"]["not"]["required"],
            json!(["bifrost"])
        );
    }
}
