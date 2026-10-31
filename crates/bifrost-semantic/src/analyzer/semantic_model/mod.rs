// Preserve explicit engine visibility when an overlay shadows a public glob.
#![allow(hidden_glob_reexports)]
// Boundary-visible child modules keep their qualified paths when short names collide.
#![allow(ambiguous_glob_reexports)]

//! Strict authoring and deterministic artifact contracts for semantic-model packs.
//!
//! Compiling a pack does not install or activate it in an analyzer. This module owns only the
//! versioned source model, validation, canonical compilation, and defensive artifact decoding.

#[doc(hidden)]
pub mod artifact;
#[doc(hidden)]
pub mod authoring;
#[doc(hidden)]
pub mod callable_values;
#[doc(hidden)]
pub mod catalog;
#[doc(hidden)]
pub mod compiler;
pub mod csmi;
#[doc(hidden)]
pub mod deferred_runtime;
#[doc(hidden)]
pub mod dependency;
#[doc(hidden)]
pub mod dependency_evidence;
#[doc(hidden)]
pub mod identity;
#[doc(hidden)]
pub mod model;
#[doc(hidden)]
pub mod overlay;
#[doc(hidden)]
pub mod producer;
#[doc(hidden)]
pub mod python_condition;
#[doc(hidden)]
pub mod runtime;
#[doc(hidden)]
pub mod runtime_contract_activation;
#[doc(hidden)]
pub mod runtime_contracts;
#[doc(hidden)]
pub mod source;
#[doc(hidden)]
pub mod validate;

pub use crate::analyzer::semantic_model::artifact::ArtifactEncoding;

pub use crate::analyzer::semantic_model::artifact::ArtifactError;

pub use crate::analyzer::semantic_model::artifact::CompiledAtomicOperation;

pub use crate::analyzer::semantic_model::artifact::CompiledClassDecoratorIdentity;

pub use crate::analyzer::semantic_model::artifact::CompiledClassDecoratorKeyword;

pub use crate::analyzer::semantic_model::artifact::CompiledConcurrencyEffect;

pub use crate::analyzer::semantic_model::artifact::CompiledCondWaiters;

pub use crate::analyzer::semantic_model::artifact::CompiledConditionalIndirectWrite;

pub use crate::analyzer::semantic_model::artifact::CompiledConditionalResultRefinement;

pub use crate::analyzer::semantic_model::artifact::CompiledDeclaredEffect;

pub use crate::analyzer::semantic_model::artifact::CompiledDeclaredEffectCertainty;

pub use crate::analyzer::semantic_model::artifact::CompiledDeclaredEffectTiming;

pub use crate::analyzer::semantic_model::artifact::CompiledIndirectWriteTarget;

pub use crate::analyzer::semantic_model::artifact::CompiledLockCondition;

pub use crate::analyzer::semantic_model::artifact::CompiledLockMode;

pub use crate::analyzer::semantic_model::artifact::CompiledNormalReturnRefinement;

pub use crate::analyzer::semantic_model::artifact::CompiledNormalReturnTypeRefinement;

pub use crate::analyzer::semantic_model::artifact::CompiledOperationPrecondition;

pub use crate::analyzer::semantic_model::artifact::CompiledPackManifest;

pub use crate::analyzer::semantic_model::artifact::CompiledPayload;

pub use crate::analyzer::semantic_model::artifact::CompiledPredicateProofEffect;

pub use crate::analyzer::semantic_model::artifact::CompiledProcedureSummary;

pub use crate::analyzer::semantic_model::artifact::CompiledProcedureTarget;

pub use crate::analyzer::semantic_model::artifact::CompiledResultContract;

pub use crate::analyzer::semantic_model::artifact::CompiledResultMemberContract;

pub use crate::analyzer::semantic_model::artifact::CompiledResultPredicate;

pub use crate::analyzer::semantic_model::artifact::CompiledResultUseObligation;

pub use crate::analyzer::semantic_model::artifact::CompiledSemanticModelPack;

pub use crate::analyzer::semantic_model::artifact::CompiledShard;

pub use crate::analyzer::semantic_model::artifact::CompiledShardArtifact;

pub use crate::analyzer::semantic_model::artifact::CompiledShardDescriptor;

pub use crate::analyzer::semantic_model::artifact::CompiledSummaryEffect;

pub use crate::analyzer::semantic_model::artifact::CompiledSummaryExitKind;

pub use crate::analyzer::semantic_model::artifact::CompiledSummaryInput;

pub use crate::analyzer::semantic_model::artifact::CompiledSummaryLocation;

pub use crate::analyzer::semantic_model::artifact::CompiledSummaryLocationKind;

pub use crate::analyzer::semantic_model::artifact::CompiledSummaryMoveInvalidation;

pub use crate::analyzer::semantic_model::artifact::CompiledSummaryOutput;

pub use crate::analyzer::semantic_model::artifact::CompiledSummaryPort;

pub use crate::analyzer::semantic_model::artifact::CompiledSummaryTransfer;

pub use crate::analyzer::semantic_model::artifact::CompiledSummaryValuePreservation;

pub use crate::analyzer::semantic_model::artifact::CompiledSummaryValueTransfer;

pub use crate::analyzer::semantic_model::artifact::CompiledSummaryValueTransferKind;

pub use crate::analyzer::semantic_model::artifact::CompiledSummaryValueTransferLimitation;

pub use crate::analyzer::semantic_model::artifact::CompiledSummaryValueTransferLimitationKind;

pub use crate::analyzer::semantic_model::artifact::CompiledSummaryValueTransferOperation;

pub use crate::analyzer::semantic_model::artifact::CompiledSyncMapOperation;

pub use crate::analyzer::semantic_model::artifact::CompiledTaskSpawnCondition;

pub use crate::analyzer::semantic_model::artifact::DecodeLimits;

pub use crate::analyzer::semantic_model::artifact::PayloadKind;

pub use crate::analyzer::semantic_model::artifact::SourceInputFile;

pub use crate::analyzer::semantic_model::artifact::SourceSetInputs;

pub use crate::analyzer::semantic_model::artifact::compiled_flow_claims_agree;

pub use crate::analyzer::semantic_model::artifact::decode_manifest;

pub use crate::analyzer::semantic_model::artifact::decode_shard;

pub use crate::analyzer::semantic_model::artifact::decode_shard_for_manifest;

pub use crate::analyzer::semantic_model::artifact::decode_validated_shard_for_manifest;

pub use crate::analyzer::semantic_model::artifact::validate_manifest_inventory;

pub use crate::analyzer::semantic_model::authoring::*;

pub use crate::analyzer::semantic_model::callable_values::*;

pub use crate::analyzer::semantic_model::catalog::*;

pub use crate::analyzer::semantic_model::compiler::CompilerOptions;

pub use crate::analyzer::semantic_model::compiler::CompressionPolicy;

pub use crate::analyzer::semantic_model::compiler::compile_pack;

pub use crate::analyzer::semantic_model::compiler::compile_source;

pub use crate::analyzer::semantic_model::compiler::lowest_schema_version;

pub use crate::analyzer::semantic_model::compiler::normalize_callable_values_payload;

pub use crate::analyzer::semantic_model::deferred_runtime::*;

pub use crate::analyzer::semantic_model::dependency::*;

pub use crate::analyzer::semantic_model::dependency_evidence::*;

pub use crate::analyzer::semantic_model::identity::MemberIdentity;

pub use crate::analyzer::semantic_model::identity::TypeIdentity;

pub use crate::analyzer::semantic_model::identity::member_declaration_id;

pub use crate::analyzer::semantic_model::identity::type_declaration_id;

pub use crate::analyzer::semantic_model::model::*;

pub use crate::analyzer::semantic_model::overlay::*;

pub use crate::analyzer::semantic_model::producer::ArtifactProducerLimits;

pub use crate::analyzer::semantic_model::producer::ArtifactProduction;

pub use crate::analyzer::semantic_model::producer::ArtifactProductionRequest;

pub use crate::analyzer::semantic_model::producer::BoundedProducerDiagnostics;

pub use crate::analyzer::semantic_model::producer::ExactArtifact;

pub use crate::analyzer::semantic_model::producer::ExactSourceEntry;

pub use crate::analyzer::semantic_model::producer::ExternalArtifactKind;

pub use crate::analyzer::semantic_model::producer::ExternalArtifactPackProducer;

pub use crate::analyzer::semantic_model::producer::ProducerDiagnostic;

pub use crate::analyzer::semantic_model::producer::ProducerDiagnosticSeverity;

pub use crate::analyzer::semantic_model::producer::read_exact_artifact;

pub use crate::analyzer::semantic_model::producer::read_exact_source_set;

#[doc(hidden)]
#[macro_export]
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
                cancellation: Option<&brokk_bifrost_core::cancellation::CancellationToken>,
            ) -> $crate::analyzer::semantic_model::ArtifactProduction {
                self.$produce(request, limits, cancellation)
            }
        }
    };
}
#[doc(hidden)]
pub use crate::implement_external_artifact_pack_producer;

pub use crate::analyzer::semantic_model::python_condition::*;

pub use crate::analyzer::semantic_model::runtime::*;

pub use crate::analyzer::semantic_model::runtime_contract_activation::*;

pub use crate::analyzer::semantic_model::runtime_contracts::*;

pub use crate::analyzer::semantic_model::source::SourceFormat;

pub(crate) use crate::analyzer::semantic_model::validate::is_canonical_relative_path;

pub use crate::analyzer::semantic_model::validate::Diagnostic;

pub use crate::analyzer::semantic_model::validate::DiagnosticSeverity;

/// Serialize a value as compact JSON bytes for deterministic ordering and digests.
pub fn compact_json_bytes<T: serde::Serialize + ?Sized>(
    value: &T,
) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(value)
}

/// Schema of the compiled manifest, including producer-only extraction authority.
pub fn compiled_manifest_json_schema() -> String {
    // Key order must not depend on whether a crate in the same build enables
    // serde_json's preserve_order feature, so sort like the authoring schema.
    let mut schema = schemars::schema_for!(CompiledPackManifest);
    let schema_object = schema.ensure_object();
    schema_object.sort_keys();
    for value in schema_object.values_mut() {
        value.sort_all_objects();
    }
    serde_json::to_string_pretty(&schema).expect("manifest schema is JSON serializable")
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

    use crate::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION;

    use crate::analyzer::semantic_model::authoring_json_schema;
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
