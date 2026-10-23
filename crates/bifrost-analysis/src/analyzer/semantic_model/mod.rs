// Preserve explicit engine visibility when an overlay shadows a public glob.
#![allow(hidden_glob_reexports)]
// Boundary-visible child modules keep their qualified paths when short names collide.
#![allow(ambiguous_glob_reexports)]

//! Strict authoring and deterministic artifact contracts for semantic-model packs.
//!
//! Compiling a pack does not install or activate it in an analyzer. This module owns only the
//! versioned source model, validation, canonical compilation, and defensive artifact decoding.

pub use brokk_bifrost_semantic::analyzer::semantic_model::*;

#[doc(hidden)]
pub mod artifact;
pub(crate) mod authoring;

#[doc(hidden)]
pub mod callable_values;
#[doc(hidden)]
pub mod catalog;
pub mod csmi;
#[doc(hidden)]
pub mod dependency;
#[doc(hidden)]
pub mod overlay;
#[doc(hidden)]
pub mod runtime;
pub use artifact::ArtifactEncoding;
pub use artifact::ArtifactError;
pub use artifact::CompiledAtomicOperation;
pub use artifact::CompiledClassDecoratorIdentity;
pub use artifact::CompiledClassDecoratorKeyword;
pub use artifact::CompiledConcurrencyEffect;
pub use artifact::CompiledCondWaiters;
pub use artifact::CompiledConditionalIndirectWrite;
pub use artifact::CompiledConditionalResultRefinement;
pub use artifact::CompiledDeclaredEffect;
pub use artifact::CompiledDeclaredEffectCertainty;
pub use artifact::CompiledDeclaredEffectTiming;
pub use artifact::CompiledIndirectWriteTarget;
pub use artifact::CompiledLockCondition;
pub use artifact::CompiledLockMode;
pub use artifact::CompiledNormalReturnRefinement;
pub use artifact::CompiledNormalReturnTypeRefinement;
pub use artifact::CompiledOperationPrecondition;
pub use artifact::CompiledPackManifest;
pub use artifact::CompiledPayload;
pub use artifact::CompiledPredicateProofEffect;
pub use artifact::CompiledProcedureSummary;
pub use artifact::CompiledProcedureTarget;
pub use artifact::CompiledResultContract;
pub use artifact::CompiledResultMemberContract;
pub use artifact::CompiledResultPredicate;
pub use artifact::CompiledResultUseObligation;
pub use artifact::CompiledSemanticModelPack;
pub use artifact::CompiledShard;
pub use artifact::CompiledShardArtifact;
pub use artifact::CompiledShardDescriptor;
pub use artifact::CompiledSummaryEffect;
pub use artifact::CompiledSummaryExitKind;
pub use artifact::CompiledSummaryInput;
pub use artifact::CompiledSummaryLocation;
pub use artifact::CompiledSummaryLocationKind;
pub use artifact::CompiledSummaryMoveInvalidation;
pub use artifact::CompiledSummaryOutput;
pub use artifact::CompiledSummaryPort;
pub use artifact::CompiledSummaryTransfer;
pub use artifact::CompiledSummaryValuePreservation;
pub use artifact::CompiledSummaryValueTransfer;
pub use artifact::CompiledSummaryValueTransferKind;
pub use artifact::CompiledSummaryValueTransferLimitation;
pub use artifact::CompiledSummaryValueTransferLimitationKind;
pub use artifact::CompiledSummaryValueTransferOperation;
pub use artifact::CompiledSyncMapOperation;
pub use artifact::CompiledTaskSpawnCondition;
pub use artifact::DecodeLimits;
pub use artifact::PayloadKind;
pub use artifact::SourceInputFile;
pub use artifact::SourceSetInputs;
pub use artifact::compiled_flow_claims_agree;
pub use artifact::decode_manifest;
pub use artifact::decode_shard;
pub use artifact::decode_shard_for_manifest;
pub use artifact::decode_validated_shard_for_manifest;
pub use artifact::validate_manifest_inventory;

pub use authoring::*;

#[doc(hidden)]
pub use brokk_bifrost_semantic::implement_external_artifact_pack_producer;

pub use callable_values::*;

pub use catalog::*;

pub use compiler::CompilerOptions;
pub use compiler::CompressionPolicy;
pub use compiler::compile_pack;
pub use compiler::compile_source;
pub use compiler::normalize_callable_values_payload;

pub use dependency::*;

pub use identity::MemberIdentity;
pub use identity::TypeIdentity;
pub use identity::member_declaration_id;
pub use identity::type_declaration_id;

#[doc(hidden)]
pub use overlay::symbol_kind_is_callable;

pub use overlay::*;

pub(crate) use producer::read_exact_artifact_while;

pub use producer::ArtifactProducerLimits;
pub use producer::ArtifactProduction;
pub use producer::ArtifactProductionRequest;
pub use producer::BoundedProducerDiagnostics;
pub use producer::ExactArtifact;
pub use producer::ExactSourceEntry;
pub use producer::ExternalArtifactKind;
pub use producer::ExternalArtifactPackProducer;
pub use producer::ProducerDiagnostic;
pub use producer::ProducerDiagnosticSeverity;
pub use producer::read_exact_artifact;
pub use producer::read_exact_source_set;

pub use runtime::*;

pub use source::SourceFormat;

pub use validate::Diagnostic;
pub use validate::DiagnosticSeverity;

#[doc(hidden)]
pub use overlay::go_method_signatures_match;
