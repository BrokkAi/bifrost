use crate::analyzer::semantic_model::conversion::authored_concurrency_effect_from_compiled;

use crate::analyzer::semantic_model::conversion::authored_declared_effect_from_compiled;

use crate::analyzer::semantic_model::conversion::authored_result_predicate_from_compiled;

use crate::analyzer::semantic_model::conversion::authored_summary_effect_from_compiled;

use crate::analyzer::semantic_model::conversion::authored_summary_input_from_compiled;

use crate::analyzer::semantic_model::conversion::authored_summary_output_from_compiled;

use crate::analyzer::semantic_model::conversion::authored_summary_value_transfer_from_compiled;

use crate::analyzer::semantic_model::model::*;

use crate::analyzer::semantic_model::validate::Diagnostic;

use crate::analyzer::semantic_model::validate::ValidationLimits;

use crate::analyzer::semantic_model::validate::is_canonical_relative_path;

use crate::analyzer::semantic_model::validate::validate_pack_locally;

use brokk_bifrost_core::analyzer::canonical_hash::hash_domain_bytes;

use brokk_bifrost_core::analyzer::canonical_hash::is_lower_sha256;

use brokk_bifrost_core::analyzer::canonical_hash::lower_hex_string;

use brokk_bifrost_core::analyzer::identifier::validate_identifier;
use brokk_bifrost_core::analyzer::model::CallableArity;
use flate2::bufread::DeflateDecoder;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::io::{Cursor, Read};

const MANIFEST_HASH_DOMAIN: &[u8] = b"bifrost.semantic-model.manifest.v1";
const SEMANTIC_HASH_DOMAIN: &[u8] = b"bifrost.semantic-model.shard.semantic.v1";
const PROCEDURE_TARGET_HASH_DOMAIN: &[u8] = b"bifrost.semantic-model.procedure-target.inventory.v1";
const PROCEDURE_ID_INVENTORY_PREFIX: &str = "procedure:";
#[doc(hidden)]
pub const PROCEDURE_TARGET_INVENTORY_PREFIX: &str = "procedure-target:";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadKind {
    DeclarationFacts,
    GeneratorRules,
    ProcedureSummaries,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactEncoding {
    Raw,
    Deflate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledShardDescriptor {
    pub shard_id: String,
    pub payload_kind: PayloadKind,
    pub routing_keys: Vec<String>,
    pub encoding: ArtifactEncoding,
    pub raw_size: u64,
    pub stored_size: u64,
    pub record_count: u64,
    pub defined_ids: Vec<String>,
    pub referenced_ids: Vec<String>,
    pub semantic_sha256: String,
    pub content_sha256: String,
    pub stored_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledPackManifest {
    pub schema_version: u32,
    pub pack_id: String,
    pub version: String,
    pub producer: Producer,
    pub language: String,
    pub ecosystem: String,
    pub compatibility: Compatibility,
    pub provenance: Provenance,
    pub license: String,
    pub completeness: Completeness,
    pub safety: Safety,
    /// The producer's claim that it parsed each of these relative source paths
    /// from a sources artifact while generating the pack (#2613); strictly
    /// ascending. Serialized only when non-empty so packs without carried
    /// sources keep byte-identical manifests and digests.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub carried_sources: Vec<String>,
    /// Exact generation inputs, independent of navigation/source locators.
    /// Omitted for packs that do not record a source-set acquisition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_inputs: Option<SourceSetInputs>,
    /// Exact native C/C++ portability evidence retained at pack scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpp_portability: Option<CppPortabilityEvidence>,
    /// Exact Python cross-artifact correspondence retained at pack scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub python_correspondence: Option<PythonCorrespondenceEvidence>,
    pub semantic_sha256: String,
    pub content_sha256: String,
    pub shards: Vec<CompiledShardDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSetInputs {
    /// Digest of the canonical exact source set, including paths and bytes.
    pub sha256: String,
    /// Actual loaded closure, in strictly ascending relative-path order.
    pub files: Vec<SourceInputFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceInputFile {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

impl CompiledPackManifest {
    pub fn matches_generated_identity(
        &self,
        producer_name: &str,
        producer_version: &str,
        schema_version: u32,
    ) -> bool {
        self.producer.name == producer_name
            && self.producer.version == producer_version
            && self.schema_version == schema_version
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledShard {
    #[doc(hidden)]
    pub schema_version: u32,
    pub(crate) pack_id: String,
    pub(crate) pack_version: String,
    pub(crate) producer: Producer,
    #[doc(hidden)]
    pub shard_id: String,
    pub(crate) language: String,
    pub(crate) ecosystem: String,
    pub(crate) compatibility: Compatibility,
    pub(crate) activation: Vec<ActivationSelector>,
    pub(crate) provenance: Provenance,
    pub(crate) license: String,
    pub(crate) completeness: Completeness,
    pub(crate) safety: Safety,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) runtime_values: Option<RuntimeValuesPayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) runtime_contracts: Option<RuntimeContractsPayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) collection_flows: Option<CollectionFlowsPayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) deferred_yields: Option<DeferredYieldsPayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) conditional_type_refinements: Option<ConditionalTypeRefinementsPayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[doc(hidden)]
    pub callable_values: Option<CallableValuesPayload>,
    /// The pack-level native C/C++ evidence is repeated in each shard wire
    /// envelope so a shard remains self-describing after extraction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cpp_portability: Option<CppPortabilityEvidence>,
    /// The pack-level Python correspondence evidence is repeated in each
    /// shard wire envelope so a shard remains self-describing after extraction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[doc(hidden)]
    pub python_correspondence: Option<PythonCorrespondenceEvidence>,
    #[doc(hidden)]
    pub payload: CompiledPayload,
}

impl CompiledShard {
    pub fn payload_kind(&self) -> PayloadKind {
        self.payload.payload_kind()
    }

    pub fn record_count(&self) -> usize {
        self.payload
            .record_count()
            .saturating_add(
                self.runtime_values
                    .as_ref()
                    .map_or(0, RuntimeValuesPayload::record_count),
            )
            .saturating_add(
                self.runtime_contracts
                    .as_ref()
                    .map_or(0, RuntimeContractsPayload::record_count),
            )
            .saturating_add(
                self.collection_flows
                    .as_ref()
                    .map_or(0, CollectionFlowsPayload::record_count),
            )
            .saturating_add(
                self.deferred_yields
                    .as_ref()
                    .map_or(0, DeferredYieldsPayload::record_count),
            )
            .saturating_add(
                self.conditional_type_refinements
                    .as_ref()
                    .map_or(0, ConditionalTypeRefinementsPayload::record_count),
            )
            .saturating_add(
                self.callable_values
                    .as_ref()
                    .map_or(0, CallableValuesPayload::record_count),
            )
    }

    pub fn pack_id(&self) -> &str {
        &self.pack_id
    }

    pub fn shard_id(&self) -> &str {
        &self.shard_id
    }

    pub fn payload(&self) -> &CompiledPayload {
        &self.payload
    }

    pub fn compatibility(&self) -> &Compatibility {
        &self.compatibility
    }

    pub fn activation(&self) -> &[ActivationSelector] {
        &self.activation
    }

    pub fn completeness(&self) -> Completeness {
        self.completeness
    }

    pub fn safety(&self) -> &Safety {
        &self.safety
    }

    pub fn cpp_portability(&self) -> Option<&CppPortabilityEvidence> {
        self.cpp_portability.as_ref()
    }

    pub fn runtime_values(&self) -> Option<&RuntimeValuesPayload> {
        self.runtime_values.as_ref()
    }

    pub fn runtime_contracts(&self) -> Option<&RuntimeContractsPayload> {
        self.runtime_contracts.as_ref()
    }

    pub fn collection_flows(&self) -> Option<&CollectionFlowsPayload> {
        self.collection_flows.as_ref()
    }

    pub fn conditional_type_refinements(&self) -> Option<&ConditionalTypeRefinementsPayload> {
        self.conditional_type_refinements.as_ref()
    }

    pub fn deferred_yields(&self) -> Option<&DeferredYieldsPayload> {
        self.deferred_yields.as_ref()
    }

    pub fn callable_values(&self) -> Option<&CallableValuesPayload> {
        self.callable_values.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CompiledPayload {
    DeclarationFacts {
        #[serde(default)]
        types: Vec<TypeFact>,
        #[serde(default)]
        members: Vec<MemberFact>,
        #[serde(default)]
        relations: Vec<RelationFact>,
    },
    GeneratorRules {
        rules: Vec<GeneratorRule>,
    },
    ProcedureSummaries {
        summaries: Vec<CompiledProcedureSummary>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledProcedureSummary {
    pub id: String,
    pub model_id: String,
    pub contract_version: u32,
    pub content_sha256: String,
    pub target: CompiledProcedureTarget,
    pub completeness: Completeness,
    /// Authored claim that this procedure and its transitive behavior do not
    /// write, publish, or escape ordinary program storage, or invoke an
    /// unaccounted callback. Synchronization bookkeeping remains represented
    /// separately.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ordinary_heap_unchanged: bool,
    /// Reviewed claim that this procedure neither synchronizes with
    /// caller-visible memory nor retains caller-visible memory for concurrent
    /// work. It is independent of ordinary-heap preservation.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_concurrency_effects: bool,
    /// The author's explicit claim that every implementation outside the
    /// workspace conforms to this summary (#2371). Serialized only when
    /// claimed, so a summary that does not claim it keeps its content digest.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub covers_overrides: bool,
    /// The reviewed claim that this procedure has no normal continuation.
    /// Serialized only when true so old compiled bytes and digests stay stable.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub normal_continuation_absent: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub normal_result_count: Option<u32>,
    pub locations: Vec<CompiledSummaryLocation>,
    pub transfers: Vec<CompiledSummaryTransfer>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transfer_partitions: Vec<NormalResultTransferPartition>,
    pub effects: Vec<CompiledSummaryEffect>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub concurrency_effects: Vec<CompiledConcurrencyEffect>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub returned_callables: Vec<CompiledReturnedCallable>,
    /// Namespaced effect identifiers declared for this exact procedure (#2437).
    /// Serialized only when non-empty, so a summary that declares none keeps the
    /// compiled bytes -- and therefore the shard digests -- it had before the
    /// field existed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declared_effects: Vec<CompiledDeclaredEffect>,
    /// Compiled mirror of the procedure-level operation-precondition review
    /// state. `None` and `Some([])` are intentionally distinct claims.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preconditions: Option<Vec<CompiledOperationPrecondition>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub result_contracts: Vec<CompiledResultContract>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub result_use_obligations: Vec<CompiledResultUseObligation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditional_result_refinements: Vec<CompiledConditionalResultRefinement>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditional_indirect_writes: Vec<CompiledConditionalIndirectWrite>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub normal_return_refinements: Vec<CompiledNormalReturnRefinement>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub normal_return_type_refinements: Vec<CompiledNormalReturnTypeRefinement>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class_decorator_identity: Option<CompiledClassDecoratorIdentity>,
}

/// Whether two compiled summaries make the same flow-observable claims.
pub fn compiled_flow_claims_agree(
    left: &CompiledProcedureSummary,
    right: &CompiledProcedureSummary,
) -> bool {
    left.completeness == right.completeness
        && left.covers_overrides == right.covers_overrides
        && left.normal_continuation_absent == right.normal_continuation_absent
        && left.normal_result_count == right.normal_result_count
        && left.locations == right.locations
        && left.transfers == right.transfers
        && left.effects == right.effects
        && left.concurrency_effects == right.concurrency_effects
        && left.returned_callables == right.returned_callables
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledClassDecoratorIdentity {
    pub direct: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub factory_keywords: Option<Vec<CompiledClassDecoratorKeyword>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledClassDecoratorKeyword {
    pub name: String,
    pub allowed_values: Vec<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledConditionalResultRefinement {
    pub result_ordinal: u32,
    pub outcome: bool,
    pub parameter_ordinal: u32,
    pub predicate: CompiledResultPredicate,
    pub proof_effect: CompiledPredicateProofEffect,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledConditionalIndirectWrite {
    pub result_ordinal: u32,
    pub outcome: bool,
    pub parameter_ordinal: u32,
    pub target: CompiledIndirectWriteTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledIndirectWriteTarget {
    Pointee,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledPredicateProofEffect {
    Establishes,
    DoesNotEstablish,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledNormalReturnRefinement {
    pub parameter_ordinal: u32,
    pub predicate: CompiledResultPredicate,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledNormalReturnTypeRefinement {
    pub parameter_ordinal: u32,
    pub class_parameter_ordinal: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_receiver_members: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledResultContract {
    pub result_ordinal: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition_result_ordinal: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predicate: Option<CompiledResultPredicate>,
    /// Reviewed predicate over the protected result. It is an independent
    /// correlation for a paired contract and the validity predicate itself
    /// for a direct contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_success_predicate: Option<CompiledResultPredicate>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub member_contracts: Vec<CompiledResultMemberContract>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledResultUseObligation {
    pub result_ordinal: u32,
    pub kind: ResultUseObligationKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_predicate: Option<CompiledResultPredicate>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledResultMemberContract {
    pub member: String,
    pub parameter_count: u32,
    pub completeness: Completeness,
    /// Compiled mirror of the operation-precondition review state. `None` and
    /// `Some([])` are intentionally distinct semantic claims.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preconditions: Option<Vec<CompiledOperationPrecondition>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declared_effects: Vec<CompiledDeclaredEffect>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledOperationPrecondition {
    pub input: CompiledSummaryInput,
    pub predicate: CompiledResultPredicate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledResultPredicate {
    Null,
    NonNull,
    True,
    False,
    Eof,
    #[serde(rename = "nonzero")]
    NonZero,
    MinusOne,
}

/// Compiled mirror of `AuthoredDeclaredEffect` (#2437).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledDeclaredEffect {
    pub id: String,
    pub timing: CompiledDeclaredEffectTiming,
    pub certainty: CompiledDeclaredEffectCertainty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledDeclaredEffectTiming {
    Immediate,
    Deferred,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledDeclaredEffectCertainty {
    Definite,
    Possible,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledProcedureTarget {
    pub path: String,
    pub symbol: String,
    pub has_receiver: bool,
    /// Compiled mirror of the authored target's variadic-tail declaration.
    /// Serialized only when true so existing fixed-arity artifacts keep their
    /// canonical bytes and semantic digests.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub variadic: bool,
    pub parameter_count: u32,
    /// Structured fixed-formal binding shape. Empty preserves legacy exact
    /// arity behavior; populated targets carry every fixed formal in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub formals: Vec<AuthoredProcedureFormal>,
}

impl CompiledProcedureTarget {
    /// Smallest actual argument count accepted by this declaration shape.
    pub const fn minimum_parameter_count(&self) -> u32 {
        if self.variadic {
            assert!(
                self.parameter_count > 0,
                "validated variadic targets declare their final formal"
            );
            self.parameter_count - 1
        } else {
            self.parameter_count
        }
    }

    /// Compact declaration shape used for applicability checks and indexes.
    pub const fn callable_arity(&self) -> CallableArity {
        CallableArity::new(
            self.minimum_parameter_count() as usize,
            self.parameter_count as usize,
            self.variadic,
        )
    }

    /// Whether an actual call arity is applicable to this declaration shape.
    pub const fn accepts_parameter_count(&self, actual: u32) -> bool {
        self.callable_arity().accepts(actual as usize)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledSummaryLocation {
    pub id: String,
    pub location_kind: CompiledSummaryLocationKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledSummaryLocationKind {
    Capture,
    Heap,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CompiledSummaryInput {
    Receiver {},
    Parameter { ordinal: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CompiledSummaryOutput {
    NormalReturn {},
    IndexedNormalReturn { ordinal: u32 },
    Receiver {},
    Capture { location: String },
    Heap { location: String },
    ExceptionalReturn {},
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CompiledSummaryPort {
    Input { input: CompiledSummaryInput },
    Output { output: CompiledSummaryOutput },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledSummaryTransfer {
    pub input: CompiledSummaryInput,
    pub exit_kind: CompiledSummaryExitKind,
    pub output: CompiledSummaryOutput,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_transfer: Option<CompiledSummaryValueTransfer>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledSummaryValueTransfer {
    pub kind: CompiledSummaryValueTransferKind,
    pub operation: CompiledSummaryValueTransferOperation,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CompiledSummaryValueTransferKind {
    Copy {},
    AggregateCopy {},
    Move {
        invalidation: CompiledSummaryMoveInvalidation,
    },
    Conversion {
        preservation: CompiledSummaryValuePreservation,
    },
    Boxing {},
    Unboxing {},
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledSummaryMoveInvalidation {
    Invalidated,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledSummaryValuePreservation {
    Identity,
    Preserving,
    Changing,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CompiledSummaryValueTransferOperation {
    None {},
    Implicit {
        member: String,
    },
    Unknown {
        limitation: CompiledSummaryValueTransferLimitation,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledSummaryValueTransferLimitation {
    pub kind: CompiledSummaryValueTransferLimitationKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledSummaryValueTransferLimitationKind {
    BudgetExhausted,
    Cancelled,
    Unsupported,
    UnresolvedIdentity,
    AmbiguousIdentity,
    IncompleteInput,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledSummaryExitKind {
    Normal,
    Exceptional,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CompiledSummaryEffect {
    Allocation {
        event: String,
        output: CompiledSummaryOutput,
    },
    Call {
        event: String,
        callee: String,
    },
    Escape {
        event: String,
        input: CompiledSummaryInput,
    },
    UnknownCall {
        event: String,
        input: CompiledSummaryInput,
    },
    UnknownCallBoundary {
        event: String,
    },
    AmbiguousCall {
        event: String,
        input: CompiledSummaryInput,
        candidates: Vec<String>,
    },
    Sanitize {
        input: CompiledSummaryInput,
        output: CompiledSummaryOutput,
        removes: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CompiledConcurrencyEffect {
    Unsupported {
        protocol: String,
    },
    TaskSpawn {
        callable: CompiledSummaryInput,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        group: Option<CompiledSummaryInput>,
        /// The spawn condition this modeled call establishes itself. `None` is
        /// an unconditional spawn; `call_result_true` is the
        /// `errgroup.Group.TryGo` contract, where the callable starts exactly
        /// when the call's boolean result reports that it did.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        condition: Option<CompiledTaskSpawnCondition>,
        /// The timer object this spawn call returns, when the spawned
        /// callback belongs to a cancellable timer (`time.AfterFunc`). A
        /// later `timer_stop` or `timer_reset` on the same object binds
        /// against this identity.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timer: Option<CompiledSummaryOutput>,
    },
    TaskJoin {
        group: CompiledSummaryInput,
    },
    /// One `sync.Once.Do` call: `callable` runs at most once per `once`
    /// object, and the completion of that single execution synchronizes
    /// before the return of every `Do` on the same object.
    ///
    /// The contract is the `sync.Once` package documentation together with
    /// the Go memory model's "the return of a call of `f` from `once.Do(f)`
    /// is synchronized before the return of any call of `once.Do(f)`". The
    /// package documentation's panic clause is part of the same completion:
    /// a panicking `f` is still considered to have returned, so later calls
    /// of `Do` return without calling `f`. This is not a mutex and not an
    /// unconditional spawn: the callable is conditional on the object's
    /// completion state, and the effect itself carries the completion
    /// barrier that publishes it.
    OnceDo {
        once: CompiledSummaryInput,
        callable: CompiledSummaryInput,
    },
    LockAcquire {
        lock: CompiledSummaryInput,
        mode: CompiledLockMode,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        condition: Option<CompiledLockCondition>,
    },
    LockRelease {
        lock: CompiledSummaryInput,
        mode: CompiledLockMode,
    },
    WaitGroupAdd {
        group: CompiledSummaryInput,
        delta: CompiledSummaryInput,
    },
    WaitGroupDone {
        group: CompiledSummaryInput,
    },
    WaitGroupWait {
        group: CompiledSummaryInput,
    },
    Atomic {
        location: CompiledSummaryInput,
        operation: CompiledAtomicOperation,
    },
    /// Associate the condition variable named by `condition` with `lock`.
    ///
    /// `condition` is the constructed object, so the association is published
    /// to the *result* of the construction call and consumed by every later
    /// `CondWait`/`CondNotify` on the same object.
    CondBind {
        condition: CompiledSummaryOutput,
        lock: CompiledSummaryInput,
    },
    /// Release the associated locker, suspend the task, and re-acquire it.
    CondWait {
        condition: CompiledSummaryInput,
    },
    /// Wake one or every suspended waiter without claiming one exists.
    CondNotify {
        condition: CompiledSummaryInput,
        waiters: CompiledCondWaiters,
    },
    /// One `sync.Map` entry operation on the (map, key) entry named by the
    /// exact receiver and key inputs. The compiled form carries the reviewed
    /// classification; the solver binds observation and guard structure.
    SyncMap {
        map: CompiledSummaryInput,
        /// The key input naming the entry; `Clear` names none.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        key: Option<CompiledSummaryInput>,
        operation: CompiledSyncMapOperation,
    },
    /// One `(*time.Timer).Stop` call: when the call's boolean result is
    /// established true, the `time.AfterFunc` callback for `timer` did not
    /// and will not run. The solver binds the guard structure.
    TimerStop {
        timer: CompiledSummaryInput,
    },
    /// One `(*time.Timer).Reset` call, which re-arms `timer` and voids the
    /// `timer_stop` cancellation downstream of it.
    TimerReset {
        timer: CompiledSummaryInput,
    },
    ChannelClose {
        channel: CompiledSummaryPort,
        fresh: bool,
    },
    ChannelCloseAsync {
        channel: CompiledSummaryPort,
        fresh: bool,
    },
    ChannelClosePropagate {
        source: CompiledSummaryPort,
        target: CompiledSummaryPort,
        target_fresh: bool,
    },
    /// One `testing.T.Run` call: `callable` is the subtest callback and
    /// `group` is the parent test node (issue #3383). The solver spawns the
    /// callback on every path and joins it at the call exactly when no
    /// execution of the callback calls `Parallel` on its own parameter.
    SubtestRun {
        callable: CompiledSummaryInput,
        group: CompiledSummaryInput,
    },
    /// One `testing.T.Parallel` call marking `receiver` (issue #3383). The
    /// solver consumes it as classification evidence for the enclosing `Run`
    /// callback; it creates no task and orders nothing by itself.
    SubtestParallel {
        receiver: CompiledSummaryInput,
    },
    /// One `testing.T.Cleanup` call: `callable` is the registered callback
    /// and `group` is the test node whose completion runs it (issue #3383).
    /// The solver spawns the callback as a deferred task and joins the
    /// receiver's subtest subtree before its body.
    SubtestCleanup {
        callable: CompiledSummaryInput,
        group: CompiledSummaryInput,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledReturnedCallable {
    pub result_ordinal: u32,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub at_most_once: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub concurrency_effects: Vec<CompiledConcurrencyEffect>,
}

/// The documented entry-level classification of one `sync.Map` operation
/// (issue #3370). See the authored form for the per-variant contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledSyncMapOperation {
    Store,
    Delete,
    Clear,
    Load,
    Range,
    LoadOrStore,
    LoadAndDelete,
    Swap,
    CompareAndSwap,
    CompareAndDelete,
}

/// How many suspended waiters one notification can resume.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledCondWaiters {
    One,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledLockMode {
    Shared,
    Exclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledLockCondition {
    CallResultTrue,
}

/// The spawn condition a compiled summary call establishes by its own boolean
/// result (issue #3371). `CallResultTrue` is `errgroup.Group.TryGo`: the
/// callable starts in a new goroutine exactly when the call reports that it
/// did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledTaskSpawnCondition {
    CallResultTrue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledAtomicOperation {
    Load,
    Store,
    ReadModifyWrite,
}

impl CompiledPayload {
    pub fn payload_kind(&self) -> PayloadKind {
        match self {
            Self::DeclarationFacts { .. } => PayloadKind::DeclarationFacts,
            Self::GeneratorRules { .. } => PayloadKind::GeneratorRules,
            Self::ProcedureSummaries { .. } => PayloadKind::ProcedureSummaries,
        }
    }

    pub fn record_count(&self) -> usize {
        match self {
            Self::DeclarationFacts {
                types,
                members,
                relations,
            } => types.len() + members.len() + relations.len(),
            Self::GeneratorRules { rules } => rules.len(),
            Self::ProcedureSummaries { summaries } => summaries.len(),
        }
    }

    pub fn declaration_facts(&self) -> Option<(&[TypeFact], &[MemberFact], &[RelationFact])> {
        match self {
            Self::DeclarationFacts {
                types,
                members,
                relations,
            } => Some((types, members, relations)),
            Self::GeneratorRules { .. } | Self::ProcedureSummaries { .. } => None,
        }
    }

    pub fn generator_rules(&self) -> Option<&[GeneratorRule]> {
        match self {
            Self::DeclarationFacts { .. } | Self::ProcedureSummaries { .. } => None,
            Self::GeneratorRules { rules } => Some(rules),
        }
    }

    pub fn procedure_summaries(&self) -> Option<&[CompiledProcedureSummary]> {
        match self {
            Self::ProcedureSummaries { summaries } => Some(summaries),
            Self::DeclarationFacts { .. } | Self::GeneratorRules { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[doc(hidden)]
pub struct WireCompiledShard {
    schema_version: u32,
    pack_id: String,
    pack_version: String,
    producer: Producer,
    shard_id: String,
    language: String,
    ecosystem: String,
    compatibility: Compatibility,
    activation: Vec<ActivationSelector>,
    provenance: Provenance,
    license: String,
    completeness: Completeness,
    safety: Safety,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    runtime_values: Option<RuntimeValuesPayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    runtime_contracts: Option<RuntimeContractsPayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    collection_flows: Option<CollectionFlowsPayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    deferred_yields: Option<DeferredYieldsPayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    conditional_type_refinements: Option<ConditionalTypeRefinementsPayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[doc(hidden)]
    pub callable_values: Option<CallableValuesPayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cpp_portability: Option<CppPortabilityEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    python_correspondence: Option<PythonCorrespondenceEvidence>,
    #[doc(hidden)]
    pub payload: CompiledPayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledShardArtifact {
    pub descriptor: CompiledShardDescriptor,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledSemanticModelPack {
    pub manifest: CompiledPackManifest,
    pub manifest_bytes: Vec<u8>,
    pub shards: Vec<CompiledShardArtifact>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeLimits {
    pub max_manifest_bytes: usize,
    pub max_stored_shard_bytes: usize,
    pub max_raw_shard_bytes: usize,
    pub max_total_raw_bytes: u64,
    pub max_shards: usize,
    pub max_records_per_shard: usize,
    pub max_total_records: u64,
    pub max_text_bytes: usize,
    pub max_depth: usize,
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            max_manifest_bytes: 16 * 1024 * 1024,
            max_stored_shard_bytes: 64 * 1024 * 1024,
            max_raw_shard_bytes: 64 * 1024 * 1024,
            max_total_raw_bytes: 1024 * 1024 * 1024,
            max_shards: 4_096,
            max_records_per_shard: 250_000,
            max_total_records: 2_000_000,
            max_text_bytes: 16 * 1024,
            max_depth: 64,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactError {
    LimitExceeded(&'static str),
    InvalidJson(String),
    UnsupportedVersion(u32),
    NonCanonical,
    InvalidDescriptor(String),
    SizeMismatch { expected: u64, actual: u64 },
    DigestMismatch(&'static str),
    SemanticValidation(Vec<Diagnostic>),
    Decompression(String),
    Allocation,
    TrailingCompressedData,
}

impl fmt::Display for ArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LimitExceeded(limit) => write!(formatter, "artifact exceeds {limit}"),
            Self::InvalidJson(error) => write!(formatter, "invalid artifact JSON: {error}"),
            Self::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "unsupported semantic-model schema version {version}"
                )
            }
            Self::NonCanonical => formatter.write_str("artifact bytes are not canonical JSON"),
            Self::InvalidDescriptor(message) => {
                write!(formatter, "invalid shard descriptor: {message}")
            }
            Self::SizeMismatch { expected, actual } => {
                write!(
                    formatter,
                    "size mismatch: expected {expected}, found {actual}"
                )
            }
            Self::DigestMismatch(kind) => write!(formatter, "{kind} digest mismatch"),
            Self::SemanticValidation(diagnostics) => write!(
                formatter,
                "artifact failed semantic validation with {} diagnostic(s)",
                diagnostics.len()
            ),
            Self::Decompression(error) => write!(formatter, "DEFLATE decode failed: {error}"),
            Self::Allocation => formatter.write_str("artifact allocation failed"),
            Self::TrailingCompressedData => {
                formatter.write_str("compressed shard has trailing data")
            }
        }
    }
}

impl std::error::Error for ArtifactError {}

pub fn decode_manifest(
    bytes: &[u8],
    limits: &DecodeLimits,
) -> Result<CompiledPackManifest, ArtifactError> {
    if bytes.len() > limits.max_manifest_bytes {
        return Err(ArtifactError::LimitExceeded("manifest byte limit"));
    }
    let manifest: CompiledPackManifest = serde_json::from_slice(bytes)
        .map_err(|error| ArtifactError::InvalidJson(error.to_string()))?;
    require_version(manifest.schema_version)?;
    manifest
        .compatibility
        .validate_for_schema(manifest.schema_version)
        .map_err(|error| ArtifactError::InvalidDescriptor(error.to_string()))?;
    if canonical_json(&manifest)? != bytes {
        return Err(ArtifactError::NonCanonical);
    }
    if manifest.shards.len() > limits.max_shards {
        return Err(ArtifactError::LimitExceeded("shard count limit"));
    }
    if validate_identifier(&manifest.pack_id, 256, true).is_err() {
        return Err(ArtifactError::InvalidDescriptor(
            "manifest pack id is invalid".to_owned(),
        ));
    }
    validate_text(&manifest.version, limits, "manifest version")?;
    validate_text(&manifest.producer.name, limits, "manifest producer name")?;
    validate_text(
        &manifest.producer.version,
        limits,
        "manifest producer version",
    )?;
    validate_text(&manifest.language, limits, "manifest language")?;
    validate_text(&manifest.ecosystem, limits, "manifest ecosystem")?;
    if let Some(requirement) = &manifest.compatibility.bifrost {
        validate_text(requirement, limits, "manifest Bifrost compatibility")?;
    }
    validate_text(&manifest.provenance.source, limits, "manifest provenance")?;
    if let Some(revision) = &manifest.provenance.revision {
        validate_text(revision, limits, "manifest provenance revision")?;
    }
    validate_text(&manifest.license, limits, "manifest license")?;
    if semver::Version::parse(&manifest.version).is_err()
        || semver::Version::parse(&manifest.producer.version).is_err()
    {
        return Err(ArtifactError::InvalidDescriptor(
            "manifest versions must be semantic versions".to_owned(),
        ));
    }
    if spdx::Expression::parse(&manifest.license).is_err() {
        return Err(ArtifactError::InvalidDescriptor(
            "manifest license must be an SPDX expression".to_owned(),
        ));
    }
    if !is_lower_sha256(&manifest.semantic_sha256) || !is_lower_sha256(&manifest.content_sha256) {
        return Err(ArtifactError::InvalidDescriptor(
            "manifest digests must be lowercase SHA-256 hex".to_owned(),
        ));
    }
    if manifest
        .compatibility
        .toolchains
        .windows(2)
        .any(|pair| (&pair[0].name, &pair[0].requirement) >= (&pair[1].name, &pair[1].requirement))
    {
        return Err(ArtifactError::InvalidDescriptor(
            "toolchain constraints must be unique and ascending".to_owned(),
        ));
    }
    for toolchain in &manifest.compatibility.toolchains {
        validate_text(&toolchain.name, limits, "toolchain name")?;
        validate_text(&toolchain.requirement, limits, "toolchain requirement")?;
        if semver::VersionReq::parse(&toolchain.requirement).is_err() {
            return Err(ArtifactError::InvalidDescriptor(
                "toolchain requirements must be semantic-version requirements".to_owned(),
            ));
        }
    }
    if manifest
        .carried_sources
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err(ArtifactError::InvalidDescriptor(
            "carried sources must be unique ascending paths".to_owned(),
        ));
    }
    for path in &manifest.carried_sources {
        validate_text(path, limits, "carried source path")?;
        if !is_canonical_relative_path(path) {
            return Err(ArtifactError::InvalidDescriptor(
                "carried sources must be relative canonical slash-separated paths".to_owned(),
            ));
        }
    }
    if let Some(inputs) = &manifest.source_inputs {
        if !is_lower_sha256(&inputs.sha256)
            || inputs.files.is_empty()
            || inputs
                .files
                .windows(2)
                .any(|pair| pair[0].path >= pair[1].path)
        {
            return Err(ArtifactError::InvalidDescriptor(
                "source inputs require a SHA-256 and unique ascending files".to_owned(),
            ));
        }
        for file in &inputs.files {
            validate_text(&file.path, limits, "source input path")?;
            if !is_canonical_relative_path(&file.path) || !is_lower_sha256(&file.sha256) {
                return Err(ArtifactError::InvalidDescriptor(
                    "source inputs require canonical relative paths and lowercase SHA-256 digests"
                        .to_owned(),
                ));
            }
        }
    }
    if manifest
        .shards
        .windows(2)
        .any(|pair| pair[0].shard_id >= pair[1].shard_id)
    {
        return Err(ArtifactError::InvalidDescriptor(
            "shard descriptors must have unique ascending ids".to_owned(),
        ));
    }
    let mut total_records = 0u64;
    let total_raw = manifest.shards.iter().try_fold(0u64, |total, shard| {
        validate_descriptor(shard, limits)?;
        total_records = total_records
            .checked_add(shard.record_count)
            .ok_or(ArtifactError::LimitExceeded("total record limit"))?;
        total
            .checked_add(shard.raw_size)
            .ok_or(ArtifactError::LimitExceeded("total raw byte limit"))
    })?;
    if total_raw > limits.max_total_raw_bytes {
        return Err(ArtifactError::LimitExceeded("total raw byte limit"));
    }
    if total_records > limits.max_total_records {
        return Err(ArtifactError::LimitExceeded("total record limit"));
    }
    validate_manifest_inventory(&manifest)?;
    if manifest_semantic_digest(&manifest)? != manifest.semantic_sha256 {
        return Err(ArtifactError::DigestMismatch("manifest semantic"));
    }
    if manifest_content_digest(&manifest)? != manifest.content_sha256 {
        return Err(ArtifactError::DigestMismatch("manifest content"));
    }
    Ok(manifest)
}

pub fn decode_shard(
    descriptor: &CompiledShardDescriptor,
    bytes: &[u8],
    limits: &DecodeLimits,
) -> Result<CompiledShard, ArtifactError> {
    let (wire, raw) = read_shard_wire(descriptor, bytes, limits)?;
    if canonical_json(&wire)? != raw {
        return Err(ArtifactError::NonCanonical);
    }
    let shard = compiled_from_wire(wire);
    let authored = authored_pack_from_compiled_shard(&shard);
    let diagnostics = validate_pack_locally(
        &authored,
        ValidationLimits {
            max_shards: 1,
            max_records_per_shard: limits.max_records_per_shard,
            max_records_per_pack: usize::try_from(limits.max_total_records).unwrap_or(usize::MAX),
            max_text_bytes: limits.max_text_bytes,
            max_depth: limits.max_depth,
        },
    );
    if !diagnostics.is_empty() {
        return Err(ArtifactError::SemanticValidation(diagnostics));
    }
    validate_compiled_procedure_metadata(&shard, &authored)?;
    if crate::analyzer::semantic_model::compiler::normalize(authored.clone()) != authored {
        return Err(ArtifactError::NonCanonical);
    }
    if shard.shard_id != descriptor.shard_id {
        return Err(ArtifactError::InvalidDescriptor(
            "shard id does not match payload".to_owned(),
        ));
    }
    if shard.payload_kind() != descriptor.payload_kind {
        return Err(ArtifactError::InvalidDescriptor(
            "payload kind does not match payload".to_owned(),
        ));
    }
    if shard.record_count() != usize::try_from(descriptor.record_count).unwrap_or(usize::MAX) {
        return Err(ArtifactError::InvalidDescriptor(
            "record count does not match payload".to_owned(),
        ));
    }
    if routing_keys(&shard.activation, &shard.payload) != descriptor.routing_keys {
        return Err(ArtifactError::InvalidDescriptor(
            "routing keys do not match payload".to_owned(),
        ));
    }
    let (defined_ids, referenced_ids) = shard_inventory(&shard);
    if defined_ids != descriptor.defined_ids || referenced_ids != descriptor.referenced_ids {
        return Err(ArtifactError::InvalidDescriptor(
            "declaration inventory does not match payload".to_owned(),
        ));
    }
    if semantic_digest(&shard)? != descriptor.semantic_sha256 {
        return Err(ArtifactError::DigestMismatch("semantic"));
    }
    Ok(shard)
}

// This performs the integrity checks needed on every read, including reads of
// previously validated bytes. Semantic validation remains in decode_shard.
#[doc(hidden)]
pub fn read_shard_wire(
    descriptor: &CompiledShardDescriptor,
    bytes: &[u8],
    limits: &DecodeLimits,
) -> Result<(WireCompiledShard, Vec<u8>), ArtifactError> {
    validate_descriptor(descriptor, limits)?;
    let actual_stored = u64::try_from(bytes.len())
        .map_err(|_| ArtifactError::LimitExceeded("stored shard byte limit"))?;
    if descriptor.stored_size != actual_stored {
        return Err(ArtifactError::SizeMismatch {
            expected: descriptor.stored_size,
            actual: actual_stored,
        });
    }
    if content_digest(bytes) != descriptor.stored_sha256 {
        return Err(ArtifactError::DigestMismatch("stored"));
    }

    let raw = match descriptor.encoding {
        ArtifactEncoding::Raw => bytes.to_vec(),
        ArtifactEncoding::Deflate => {
            let _scope = brokk_bifrost_core::profiling::scope("semantic_pack.inflate_shard");
            inflate_bounded(bytes, descriptor.raw_size, limits)?
        }
    };
    let actual_raw = u64::try_from(raw.len())
        .map_err(|_| ArtifactError::LimitExceeded("raw shard byte limit"))?;
    if descriptor.raw_size != actual_raw {
        return Err(ArtifactError::SizeMismatch {
            expected: descriptor.raw_size,
            actual: actual_raw,
        });
    }
    if content_digest(&raw) != descriptor.content_sha256 {
        return Err(ArtifactError::DigestMismatch("content"));
    }
    let wire: WireCompiledShard = {
        let _scope = brokk_bifrost_core::profiling::scope("semantic_pack.parse_shard_json");
        serde_json::from_slice(&raw)
            .map_err(|error| ArtifactError::InvalidJson(error.to_string()))?
    };
    require_version(wire.schema_version)?;
    Ok((wire, raw))
}

/// Hydrate bytes with a current catalog validation certificate. The catalog
/// must bind that certificate to this exact manifest, descriptor, and limits.
/// Content digests and the manifest envelope are checked on every read.
#[doc(hidden)]
pub fn hydrate_certified_shard(
    manifest: &CompiledPackManifest,
    descriptor: &CompiledShardDescriptor,
    bytes: &[u8],
    limits: &DecodeLimits,
) -> Result<CompiledShard, ArtifactError> {
    let (wire, _raw) = read_shard_wire(descriptor, bytes, limits)?;
    let shard = compiled_from_wire(wire);
    validate_shard_envelope(manifest, descriptor, &shard)?;
    Ok(shard)
}

fn validate_compiled_procedure_metadata(
    shard: &CompiledShard,
    authored: &AuthoredSemanticModelPack,
) -> Result<(), ArtifactError> {
    let CompiledPayload::ProcedureSummaries { summaries } = &shard.payload else {
        return Ok(());
    };
    let AuthoredPayload::ProcedureSummaries {
        summaries: authored_summaries,
    } = &authored.shards[0].payload
    else {
        return Err(ArtifactError::InvalidDescriptor(
            "compiled procedure payload did not reconstruct as authored procedures".to_owned(),
        ));
    };
    if summaries.len() != authored_summaries.len() {
        return Err(ArtifactError::InvalidDescriptor(
            "compiled procedure record count changed during reconstruction".to_owned(),
        ));
    }
    for (compiled, authored) in summaries.iter().zip(authored_summaries) {
        if compiled.contract_version != PROCEDURE_SUMMARY_CONTRACT_VERSION {
            return Err(ArtifactError::InvalidDescriptor(
                "procedure summary contract version is unsupported".to_owned(),
            ));
        }
        if compiled.model_id != format!("{}#{}", shard.pack_id, compiled.id) {
            return Err(ArtifactError::InvalidDescriptor(
                "procedure summary model id was not derived from the pack and record ids"
                    .to_owned(),
            ));
        }
        if !is_lower_sha256(&compiled.content_sha256)
            || compiled.content_sha256 != content_digest(&canonical_json(authored)?)
        {
            return Err(ArtifactError::InvalidDescriptor(
                "procedure summary content hash is invalid".to_owned(),
            ));
        }
    }
    Ok(())
}

#[doc(hidden)]
pub fn compiled_from_wire(wire: WireCompiledShard) -> CompiledShard {
    CompiledShard {
        schema_version: wire.schema_version,
        pack_id: wire.pack_id,
        pack_version: wire.pack_version,
        producer: wire.producer,
        shard_id: wire.shard_id,
        language: wire.language,
        ecosystem: wire.ecosystem,
        compatibility: wire.compatibility,
        activation: wire.activation,
        provenance: wire.provenance,
        license: wire.license,
        completeness: wire.completeness,
        safety: wire.safety,
        runtime_values: wire.runtime_values,
        runtime_contracts: wire.runtime_contracts,
        collection_flows: wire.collection_flows,
        deferred_yields: wire.deferred_yields,
        conditional_type_refinements: wire.conditional_type_refinements,
        callable_values: wire.callable_values,
        cpp_portability: wire.cpp_portability,
        python_correspondence: wire.python_correspondence,
        payload: wire.payload,
    }
}

pub fn decode_shard_for_manifest(
    manifest: &CompiledPackManifest,
    descriptor: &CompiledShardDescriptor,
    bytes: &[u8],
    limits: &DecodeLimits,
) -> Result<CompiledShard, ArtifactError> {
    validate_manifest_inventory(manifest)?;
    decode_present_shard_for_manifest(manifest, descriptor, bytes, limits)
}

/// Decode one shard of a manifest whose inventory the caller already validated.
///
/// [`validate_manifest_inventory`] proves properties of the whole manifest and
/// never looks at one shard's bytes, so a reader that decodes every shard of a
/// manifest validates it once and decodes the rest through this entry point
/// (#3101). A caller that has not validated the inventory must not use it.
pub fn decode_validated_shard_for_manifest(
    manifest: &CompiledPackManifest,
    descriptor: &CompiledShardDescriptor,
    bytes: &[u8],
    limits: &DecodeLimits,
) -> Result<CompiledShard, ArtifactError> {
    decode_present_shard_for_manifest(manifest, descriptor, bytes, limits)
}

fn decode_present_shard_for_manifest(
    manifest: &CompiledPackManifest,
    descriptor: &CompiledShardDescriptor,
    bytes: &[u8],
    limits: &DecodeLimits,
) -> Result<CompiledShard, ArtifactError> {
    let shard = decode_shard(descriptor, bytes, limits)?;
    validate_shard_envelope(manifest, descriptor, &shard)?;
    Ok(shard)
}

fn validate_shard_envelope(
    manifest: &CompiledPackManifest,
    descriptor: &CompiledShardDescriptor,
    shard: &CompiledShard,
) -> Result<(), ArtifactError> {
    if !manifest
        .shards
        .iter()
        .any(|candidate| candidate == descriptor)
    {
        return Err(ArtifactError::InvalidDescriptor(
            "shard descriptor is not present in manifest".to_owned(),
        ));
    }
    if shard.schema_version != manifest.schema_version
        || shard.pack_id != manifest.pack_id
        || shard.pack_version != manifest.version
        || shard.producer != manifest.producer
        || shard.language != manifest.language
        || shard.ecosystem != manifest.ecosystem
        || shard.compatibility != manifest.compatibility
        || shard.provenance != manifest.provenance
        || shard.license != manifest.license
        || shard.completeness != manifest.completeness
        || shard.safety != manifest.safety
    {
        return Err(ArtifactError::InvalidDescriptor(
            "shard envelope does not match manifest".to_owned(),
        ));
    }
    Ok(())
}

fn inflate_bounded(
    bytes: &[u8],
    declared_raw_size: u64,
    limits: &DecodeLimits,
) -> Result<Vec<u8>, ArtifactError> {
    if declared_raw_size > limits.max_raw_shard_bytes as u64 {
        return Err(ArtifactError::LimitExceeded("raw shard byte limit"));
    }
    let capacity = usize::try_from(declared_raw_size)
        .map_err(|_| ArtifactError::LimitExceeded("raw shard byte limit"))?;
    let mut decoder = DeflateDecoder::new(Cursor::new(bytes));
    let mut output = Vec::new();
    output
        .try_reserve(capacity.min(16 * 1024))
        .map_err(|_| ArtifactError::Allocation)?;
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = decoder
            .read(&mut buffer)
            .map_err(|error| ArtifactError::Decompression(error.to_string()))?;
        if read == 0 {
            break;
        }
        if output.len().saturating_add(read) > capacity
            || output.len().saturating_add(read) > limits.max_raw_shard_bytes
        {
            return Err(ArtifactError::LimitExceeded("raw shard byte limit"));
        }
        output
            .try_reserve(read)
            .map_err(|_| ArtifactError::Allocation)?;
        output.extend_from_slice(&buffer[..read]);
    }
    if decoder.total_in() != bytes.len() as u64 {
        return Err(ArtifactError::TrailingCompressedData);
    }
    Ok(output)
}

fn validate_descriptor(
    descriptor: &CompiledShardDescriptor,
    limits: &DecodeLimits,
) -> Result<(), ArtifactError> {
    if validate_identifier(&descriptor.shard_id, 256, true).is_err() {
        return Err(ArtifactError::InvalidDescriptor(
            "shard id is invalid".to_owned(),
        ));
    }
    if descriptor
        .routing_keys
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err(ArtifactError::InvalidDescriptor(
            "routing keys must be unique and ascending".to_owned(),
        ));
    }
    for (name, ids) in [
        ("defined ids", &descriptor.defined_ids),
        ("referenced ids", &descriptor.referenced_ids),
    ] {
        if ids.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ArtifactError::InvalidDescriptor(format!(
                "{name} must be unique and ascending"
            )));
        }
        if ids.iter().any(|id| !valid_inventory_id(id)) {
            return Err(ArtifactError::InvalidDescriptor(format!(
                "{name} must contain valid stable ids"
            )));
        }
    }
    if descriptor.stored_size > limits.max_stored_shard_bytes as u64 {
        return Err(ArtifactError::LimitExceeded("stored shard byte limit"));
    }
    if descriptor.raw_size > limits.max_raw_shard_bytes as u64 {
        return Err(ArtifactError::LimitExceeded("raw shard byte limit"));
    }
    if descriptor.record_count > limits.max_records_per_shard as u64 {
        return Err(ArtifactError::LimitExceeded("records per shard limit"));
    }
    if descriptor.encoding == ArtifactEncoding::Raw && descriptor.raw_size != descriptor.stored_size
    {
        return Err(ArtifactError::InvalidDescriptor(
            "raw shards must have equal raw and stored sizes".to_owned(),
        ));
    }
    for digest in [
        &descriptor.semantic_sha256,
        &descriptor.content_sha256,
        &descriptor.stored_sha256,
    ] {
        if !is_lower_sha256(digest) {
            return Err(ArtifactError::InvalidDescriptor(
                "digests must be lowercase SHA-256 hex".to_owned(),
            ));
        }
    }
    Ok(())
}

#[doc(hidden)]
pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, ArtifactError> {
    crate::analyzer::semantic_model::compact_json_bytes(value)
        .map_err(|error| ArtifactError::InvalidJson(error.to_string()))
}

#[doc(hidden)]
pub fn semantic_digest(shard: &CompiledShard) -> Result<String, ArtifactError> {
    #[derive(Serialize)]
    struct SemanticView<'a> {
        schema_version: u32,
        pack_id: &'a str,
        shard_id: &'a str,
        language: &'a str,
        ecosystem: &'a str,
        compatibility: &'a Compatibility,
        activation: &'a [ActivationSelector],
        completeness: Completeness,
        safety: &'a Safety,
        #[serde(skip_serializing_if = "Option::is_none")]
        runtime_values: &'a Option<RuntimeValuesPayload>,
        #[serde(skip_serializing_if = "Option::is_none")]
        runtime_contracts: &'a Option<RuntimeContractsPayload>,
        #[serde(skip_serializing_if = "Option::is_none")]
        collection_flows: &'a Option<CollectionFlowsPayload>,
        #[serde(skip_serializing_if = "Option::is_none")]
        deferred_yields: &'a Option<DeferredYieldsPayload>,
        #[serde(skip_serializing_if = "Option::is_none")]
        conditional_type_refinements: &'a Option<ConditionalTypeRefinementsPayload>,
        #[serde(skip_serializing_if = "Option::is_none")]
        callable_values: &'a Option<CallableValuesPayload>,
        #[serde(skip_serializing_if = "Option::is_none")]
        cpp_portability: &'a Option<CppPortabilityEvidence>,
        #[serde(skip_serializing_if = "Option::is_none")]
        python_correspondence: &'a Option<PythonCorrespondenceEvidence>,
        payload: &'a CompiledPayload,
    }
    let bytes = canonical_json(&SemanticView {
        schema_version: shard.schema_version,
        pack_id: &shard.pack_id,
        shard_id: &shard.shard_id,
        language: &shard.language,
        ecosystem: &shard.ecosystem,
        compatibility: &shard.compatibility,
        activation: &shard.activation,
        completeness: shard.completeness,
        safety: &shard.safety,
        runtime_values: &shard.runtime_values,
        runtime_contracts: &shard.runtime_contracts,
        collection_flows: &shard.collection_flows,
        deferred_yields: &shard.deferred_yields,
        conditional_type_refinements: &shard.conditional_type_refinements,
        callable_values: &shard.callable_values,
        cpp_portability: &shard.cpp_portability,
        python_correspondence: &shard.python_correspondence,
        payload: &shard.payload,
    })?;
    Ok(digest_hex(SEMANTIC_HASH_DOMAIN, &bytes))
}

#[doc(hidden)]
pub fn manifest_semantic_digest(manifest: &CompiledPackManifest) -> Result<String, ArtifactError> {
    #[derive(Serialize)]
    struct ManifestSemanticView<'a> {
        schema_version: u32,
        pack_id: &'a str,
        version: &'a str,
        language: &'a str,
        ecosystem: &'a str,
        compatibility: &'a Compatibility,
        completeness: Completeness,
        safety: &'a Safety,
        #[serde(skip_serializing_if = "Option::is_none")]
        cpp_portability: &'a Option<CppPortabilityEvidence>,
        #[serde(skip_serializing_if = "Option::is_none")]
        python_correspondence: &'a Option<PythonCorrespondenceEvidence>,
        shards: Vec<(&'a str, &'a str)>,
    }
    let bytes = canonical_json(&ManifestSemanticView {
        schema_version: manifest.schema_version,
        pack_id: &manifest.pack_id,
        version: &manifest.version,
        language: &manifest.language,
        ecosystem: &manifest.ecosystem,
        compatibility: &manifest.compatibility,
        completeness: manifest.completeness,
        safety: &manifest.safety,
        cpp_portability: &manifest.cpp_portability,
        python_correspondence: &manifest.python_correspondence,
        shards: manifest
            .shards
            .iter()
            .map(|shard| (shard.shard_id.as_str(), shard.semantic_sha256.as_str()))
            .collect(),
    })?;
    Ok(digest_hex(MANIFEST_HASH_DOMAIN, &bytes))
}

#[doc(hidden)]
pub fn manifest_content_digest(manifest: &CompiledPackManifest) -> Result<String, ArtifactError> {
    #[derive(Serialize)]
    struct ManifestContentView<'a> {
        schema_version: u32,
        pack_id: &'a str,
        version: &'a str,
        producer: &'a Producer,
        language: &'a str,
        ecosystem: &'a str,
        compatibility: &'a Compatibility,
        provenance: &'a Provenance,
        license: &'a str,
        completeness: Completeness,
        safety: &'a Safety,
        #[serde(skip_serializing_if = "Option::is_none")]
        cpp_portability: &'a Option<CppPortabilityEvidence>,
        #[serde(skip_serializing_if = "Option::is_none")]
        python_correspondence: &'a Option<PythonCorrespondenceEvidence>,
        #[serde(skip_serializing_if = "<[String]>::is_empty")]
        carried_sources: &'a [String],
        #[serde(skip_serializing_if = "Option::is_none")]
        source_inputs: &'a Option<SourceSetInputs>,
        semantic_sha256: &'a str,
        shards: &'a [CompiledShardDescriptor],
    }
    let bytes = canonical_json(&ManifestContentView {
        schema_version: manifest.schema_version,
        pack_id: &manifest.pack_id,
        version: &manifest.version,
        producer: &manifest.producer,
        language: &manifest.language,
        ecosystem: &manifest.ecosystem,
        compatibility: &manifest.compatibility,
        provenance: &manifest.provenance,
        license: &manifest.license,
        completeness: manifest.completeness,
        safety: &manifest.safety,
        cpp_portability: &manifest.cpp_portability,
        python_correspondence: &manifest.python_correspondence,
        carried_sources: &manifest.carried_sources,
        source_inputs: &manifest.source_inputs,
        semantic_sha256: &manifest.semantic_sha256,
        shards: &manifest.shards,
    })?;
    Ok(content_digest(&bytes))
}

#[doc(hidden)]
pub fn content_digest(bytes: &[u8]) -> String {
    crate::analyzer::semantic_model::csmi::sha256_hex(bytes)
}

pub(crate) fn routing_keys(
    selectors: &[ActivationSelector],
    payload: &CompiledPayload,
) -> Vec<String> {
    let mut keys = Vec::new();
    for selector in selectors {
        for (prefix, selected) in [
            ("package", selector.package.as_ref()),
            ("module", selector.module.as_ref()),
            ("toolchain", selector.toolchain.as_ref()),
        ] {
            if let Some(selected) = selected {
                keys.push(format!("{prefix}:{}", selected.name));
            }
        }
    }
    if let CompiledPayload::GeneratorRules { rules } = payload {
        for rule in rules {
            let kind = match rule.trigger {
                RuleTrigger::LanguageConstruct { .. } => "language_construct",
                RuleTrigger::Annotation { .. } => "annotation",
                RuleTrigger::AnnotatedField { .. } => "annotated_field",
                RuleTrigger::MacroInvocation { .. } => "macro_invocation",
                RuleTrigger::GeneratorInvocation { .. } => "generator_invocation",
                RuleTrigger::ResolvedOwner { .. } => "resolved_owner",
                RuleTrigger::ResolvedCall { .. } => "resolved_call",
            };
            keys.push(format!("trigger:{kind}"));
        }
    }
    if matches!(payload, CompiledPayload::ProcedureSummaries { .. }) {
        keys.push("payload:procedure_summaries".to_owned());
    }
    keys.sort_unstable();
    keys.dedup();
    keys
}

pub(crate) fn shard_inventory(shard: &CompiledShard) -> (Vec<String>, Vec<String>) {
    use crate::analyzer::semantic_model::csmi::CsmiCallableValuesArgument;

    use crate::analyzer::semantic_model::csmi::CsmiCallableValuesPayload;

    use crate::analyzer::semantic_model::csmi::CsmiConditionalTypeOutcome;

    use crate::analyzer::semantic_model::csmi::CsmiTypeExpression;
    let (mut defined, mut referenced) = payload_inventory(&shard.payload);
    if let Some(payload) = &shard.conditional_type_refinements {
        let mut pending = Vec::new();
        for fact in &payload.refinements {
            referenced.push(fact.payload.callable.clone());
            if let CsmiConditionalTypeOutcome::Supported { target, .. } = &fact.payload.outcome {
                pending.push(target);
            }
        }
        while let Some(target) = pending.pop() {
            match target {
                CsmiTypeExpression::Reference(reference) => {
                    referenced.push(reference.symbol.clone());
                    pending.extend(&reference.arguments);
                }
                CsmiTypeExpression::Parameter(parameter) => {
                    referenced.push(parameter.symbol.clone())
                }
                CsmiTypeExpression::Intrinsic(_) => {}
                CsmiTypeExpression::Unknown(_) => {}
            }
        }
    }
    if let Some(payload) = &shard.callable_values {
        defined.extend(
            payload
                .anonymous_callables
                .iter()
                .map(|identity| identity.id.clone()),
        );
        for fact in &payload.facts {
            match &fact.payload {
                CsmiCallableValuesPayload::ReturnedCallable {
                    callable, target, ..
                } => {
                    referenced.push(callable.clone());
                    referenced.push(target.clone());
                }
                CsmiCallableValuesPayload::CallbackInvocation {
                    callable,
                    callback,
                    arguments,
                    ..
                } => {
                    referenced.push(callable.clone());
                    callable_values_location_inventory(callback, &mut referenced);
                    for argument in arguments {
                        if let CsmiCallableValuesArgument::Input { source } = argument {
                            callable_values_location_inventory(source, &mut referenced);
                        }
                    }
                }
            }
        }
        referenced.extend(
            payload
                .coverage
                .iter()
                .map(|coverage| coverage.callable.clone()),
        );
    }
    defined.sort_unstable();
    defined.dedup();
    referenced.sort_unstable();
    referenced.dedup();
    (defined, referenced)
}

fn callable_values_location_inventory(
    location: &crate::analyzer::semantic_model::csmi::CsmiInputLocation,
    referenced: &mut Vec<String>,
) {
    if let crate::analyzer::semantic_model::csmi::CsmiInputBoundaryRoot::Capture(root) =
        &location.root
    {
        referenced.push(root.symbol.clone());
    }
    let Some(projection) = &location.projection else {
        return;
    };
    for step in &projection.steps {
        if let Some(symbol) = step
            .args
            .as_ref()
            .and_then(|args| args.get("symbol"))
            .and_then(serde_json::Value::as_str)
        {
            referenced.push(symbol.to_owned());
        }
    }
}

#[doc(hidden)]
pub fn payload_inventory(payload: &CompiledPayload) -> (Vec<String>, Vec<String>) {
    let mut defined = HashSet::new();
    let mut referenced = HashSet::new();
    match payload {
        CompiledPayload::DeclarationFacts {
            types,
            members,
            relations,
        } => {
            for fact in types {
                defined.insert(fact.id.clone());
                for hierarchy in &fact.hierarchy {
                    collect_declared_type_refs(&hierarchy.target, &mut referenced);
                }
                for base in fact.runtime_bases.iter().flatten() {
                    collect_declared_type_refs(base, &mut referenced);
                }
                for constraint in &fact.type_parameter_constraints {
                    for type_ref in &constraint.constraint.referenced_types {
                        collect_declared_type_refs(type_ref, &mut referenced);
                    }
                }
                if let Some(underlying) = &fact.underlying_type {
                    for type_ref in &underlying.referenced_types {
                        collect_declared_type_refs(type_ref, &mut referenced);
                    }
                }
                if let Some(TypeValueSemantics {
                    copy: Some(TypeCopySemantics::ViaMember { member }),
                    ..
                }) = &fact.value_semantics
                {
                    referenced.insert(member.clone());
                }
                for embedded in &fact.embedded_types {
                    collect_declared_type_refs(&embedded.target, &mut referenced);
                }
            }
            for fact in members {
                defined.insert(fact.id.clone());
                referenced.insert(fact.owner.clone());
                if let Some(signature) = &fact.signature {
                    for parameter in &signature.parameters {
                        collect_declared_type_refs(&parameter.r#type, &mut referenced);
                    }
                    if let Some(returns) = &signature.returns {
                        collect_declared_type_refs(returns, &mut referenced);
                    }
                }
                if let Some(ImplicitOperation::ConversionOperator { target }) =
                    &fact.implicit_operation
                {
                    collect_declared_type_refs(target, &mut referenced);
                }
            }
            for relation in relations {
                referenced.insert(relation.from.clone());
                referenced.insert(relation.to.clone());
            }
        }
        CompiledPayload::ProcedureSummaries { summaries } => {
            for summary in summaries {
                defined.insert(format!("{PROCEDURE_ID_INVENTORY_PREFIX}{}", summary.id));
                defined.insert(procedure_target_inventory_id(&summary.target));
                for transfer in &summary.transfers {
                    if let Some(CompiledSummaryValueTransfer {
                        operation: CompiledSummaryValueTransferOperation::Implicit { member },
                        ..
                    }) = &transfer.value_transfer
                    {
                        referenced.insert(member.clone());
                    }
                }
                for effect in &summary.effects {
                    match effect {
                        CompiledSummaryEffect::Call { callee, .. } => {
                            referenced.insert(format!("{PROCEDURE_ID_INVENTORY_PREFIX}{callee}"));
                        }
                        CompiledSummaryEffect::AmbiguousCall { candidates, .. } => {
                            referenced.extend(candidates.iter().map(|candidate| {
                                format!("{PROCEDURE_ID_INVENTORY_PREFIX}{candidate}")
                            }));
                        }
                        CompiledSummaryEffect::Allocation { .. }
                        | CompiledSummaryEffect::Escape { .. }
                        | CompiledSummaryEffect::UnknownCall { .. }
                        | CompiledSummaryEffect::UnknownCallBoundary { .. }
                        | CompiledSummaryEffect::Sanitize { .. } => {}
                    }
                }
            }
        }
        CompiledPayload::GeneratorRules { .. } => {}
    }
    let mut defined: Vec<_> = defined.into_iter().collect();
    let mut referenced: Vec<_> = referenced.into_iter().collect();
    defined.sort_unstable();
    referenced.sort_unstable();
    (defined, referenced)
}

fn procedure_target_inventory_id(target: &CompiledProcedureTarget) -> String {
    let bytes = canonical_json(&(target.path.as_str(), target.symbol.as_str()))
        .expect("procedure target identity is JSON serializable");
    format!(
        "{PROCEDURE_TARGET_INVENTORY_PREFIX}{}",
        digest_hex(PROCEDURE_TARGET_HASH_DOMAIN, &bytes)
    )
}

fn valid_inventory_id(id: &str) -> bool {
    if let Some(procedure_id) = id.strip_prefix(PROCEDURE_ID_INVENTORY_PREFIX) {
        validate_identifier(procedure_id, 256, true).is_ok()
    } else if let Some(target_digest) = id.strip_prefix(PROCEDURE_TARGET_INVENTORY_PREFIX) {
        is_lower_sha256(target_digest)
    } else {
        validate_identifier(id, 256, true).is_ok()
    }
}

fn collect_declared_type_refs(root: &TypeRef, ids: &mut HashSet<String>) {
    crate::analyzer::semantic::common::visit_declared_type_refs(std::iter::once(root), |id| {
        ids.insert(id.to_owned());
    });
}

fn authored_pack_from_compiled_shard(shard: &CompiledShard) -> AuthoredSemanticModelPack {
    AuthoredSemanticModelPack {
        schema_version: shard.schema_version,
        pack_id: shard.pack_id.clone(),
        version: shard.pack_version.clone(),
        producer: shard.producer.clone(),
        language: shard.language.clone(),
        ecosystem: shard.ecosystem.clone(),
        compatibility: shard.compatibility.clone(),
        provenance: shard.provenance.clone(),
        license: shard.license.clone(),
        completeness: shard.completeness,
        safety: shard.safety.clone(),
        carried_sources: Vec::new(),
        cpp_portability: shard.cpp_portability.clone(),
        python_correspondence: shard.python_correspondence.clone(),
        shards: vec![authored_shard_from_compiled(shard)],
    }
}

#[doc(hidden)]
pub fn authored_pack_from_decoded_shards(
    manifest: &CompiledPackManifest,
    shards: &[CompiledShard],
) -> AuthoredSemanticModelPack {
    AuthoredSemanticModelPack {
        schema_version: manifest.schema_version,
        pack_id: manifest.pack_id.clone(),
        version: manifest.version.clone(),
        producer: manifest.producer.clone(),
        language: manifest.language.clone(),
        ecosystem: manifest.ecosystem.clone(),
        compatibility: manifest.compatibility.clone(),
        provenance: manifest.provenance.clone(),
        license: manifest.license.clone(),
        completeness: manifest.completeness,
        safety: manifest.safety.clone(),
        carried_sources: manifest.carried_sources.clone(),
        cpp_portability: manifest.cpp_portability.clone(),
        python_correspondence: manifest.python_correspondence.clone(),
        shards: shards.iter().map(authored_shard_from_compiled).collect(),
    }
}

fn authored_shard_from_compiled(shard: &CompiledShard) -> AuthoredShard {
    AuthoredShard {
        id: shard.shard_id.clone(),
        activation: shard.activation.clone(),
        payload: authored_payload_from_compiled(&shard.payload),
        runtime_values: shard.runtime_values.clone(),
        runtime_contracts: shard.runtime_contracts.clone(),
        collection_flows: shard.collection_flows.clone(),
        deferred_yields: shard.deferred_yields.clone(),
        conditional_type_refinements: shard.conditional_type_refinements.clone(),
        callable_values: shard.callable_values.clone(),
    }
}

fn authored_payload_from_compiled(payload: &CompiledPayload) -> AuthoredPayload {
    match payload {
        CompiledPayload::DeclarationFacts {
            types,
            members,
            relations,
        } => AuthoredPayload::DeclarationFacts {
            types: types.clone(),
            members: members.clone(),
            relations: relations.clone(),
        },
        CompiledPayload::GeneratorRules { rules } => AuthoredPayload::GeneratorRules {
            rules: rules.clone(),
        },
        CompiledPayload::ProcedureSummaries { summaries } => AuthoredPayload::ProcedureSummaries {
            summaries: summaries
                .iter()
                .map(authored_procedure_summary_from_compiled)
                .collect(),
        },
    }
}

#[doc(hidden)]
pub fn authored_procedure_summary_from_compiled(
    summary: &CompiledProcedureSummary,
) -> AuthoredProcedureSummary {
    AuthoredProcedureSummary {
        id: summary.id.clone(),
        target: AuthoredProcedureTarget {
            path: summary.target.path.clone(),
            symbol: summary.target.symbol.clone(),
            has_receiver: summary.target.has_receiver,
            variadic: summary.target.variadic,
            parameter_count: summary.target.parameter_count,
            formals: summary.target.formals.clone(),
        },
        completeness: summary.completeness,
        ordinary_heap_unchanged: summary.ordinary_heap_unchanged,
        no_concurrency_effects: summary.no_concurrency_effects,
        covers_overrides: summary.covers_overrides,
        normal_continuation_absent: summary.normal_continuation_absent,
        normal_result_count: summary.normal_result_count,
        locations: summary
            .locations
            .iter()
            .map(|location| AuthoredSummaryLocation {
                id: location.id.clone(),
                location_kind: match location.location_kind {
                    CompiledSummaryLocationKind::Capture => AuthoredSummaryLocationKind::Capture,
                    CompiledSummaryLocationKind::Heap => AuthoredSummaryLocationKind::Heap,
                },
            })
            .collect(),
        transfers: summary
            .transfers
            .iter()
            .map(|transfer| AuthoredSummaryTransfer {
                input: authored_summary_input_from_compiled(&transfer.input),
                exit_kind: match transfer.exit_kind {
                    CompiledSummaryExitKind::Normal => AuthoredSummaryExitKind::Normal,
                    CompiledSummaryExitKind::Exceptional => AuthoredSummaryExitKind::Exceptional,
                },
                output: authored_summary_output_from_compiled(&transfer.output),
                value_transfer: transfer
                    .value_transfer
                    .as_ref()
                    .map(authored_summary_value_transfer_from_compiled),
            })
            .collect(),
        transfer_partitions: summary.transfer_partitions.clone(),
        effects: summary
            .effects
            .iter()
            .map(authored_summary_effect_from_compiled)
            .collect(),
        concurrency_effects: summary
            .concurrency_effects
            .iter()
            .map(authored_concurrency_effect_from_compiled)
            .collect(),
        returned_callables: summary
            .returned_callables
            .iter()
            .map(|callable| AuthoredReturnedCallable {
                result_ordinal: callable.result_ordinal,
                at_most_once: callable.at_most_once,
                concurrency_effects: callable
                    .concurrency_effects
                    .iter()
                    .map(authored_concurrency_effect_from_compiled)
                    .collect(),
            })
            .collect(),
        declared_effects: summary
            .declared_effects
            .iter()
            .map(authored_declared_effect_from_compiled)
            .collect(),
        preconditions: summary.preconditions.as_ref().map(|preconditions| {
            preconditions
                .iter()
                .map(|precondition| AuthoredOperationPrecondition {
                    input: authored_summary_input_from_compiled(&precondition.input),
                    predicate: authored_result_predicate_from_compiled(precondition.predicate),
                })
                .collect()
        }),
        result_contracts: summary
            .result_contracts
            .iter()
            .map(|contract| AuthoredResultContract {
                result_ordinal: contract.result_ordinal,
                condition_result_ordinal: contract.condition_result_ordinal,
                predicate: contract
                    .predicate
                    .map(authored_result_predicate_from_compiled),
                result_success_predicate: contract
                    .result_success_predicate
                    .map(authored_result_predicate_from_compiled),
                member_contracts: contract
                    .member_contracts
                    .iter()
                    .map(|member| AuthoredResultMemberContract {
                        member: member.member.clone(),
                        parameter_count: member.parameter_count,
                        completeness: member.completeness,
                        preconditions: member.preconditions.as_ref().map(|preconditions| {
                            preconditions
                                .iter()
                                .map(|precondition| AuthoredOperationPrecondition {
                                    input: authored_summary_input_from_compiled(
                                        &precondition.input,
                                    ),
                                    predicate: authored_result_predicate_from_compiled(
                                        precondition.predicate,
                                    ),
                                })
                                .collect()
                        }),
                        declared_effects: member
                            .declared_effects
                            .iter()
                            .map(authored_declared_effect_from_compiled)
                            .collect(),
                    })
                    .collect(),
            })
            .collect(),
        result_use_obligations: summary
            .result_use_obligations
            .iter()
            .map(|obligation| AuthoredResultUseObligation {
                result_ordinal: obligation.result_ordinal,
                kind: obligation.kind,
                failure_predicate: obligation
                    .failure_predicate
                    .map(authored_result_predicate_from_compiled),
            })
            .collect(),
        conditional_result_refinements: summary
            .conditional_result_refinements
            .iter()
            .map(|refinement| AuthoredConditionalResultRefinement {
                result_ordinal: refinement.result_ordinal,
                outcome: refinement.outcome,
                parameter_ordinal: refinement.parameter_ordinal,
                predicate: authored_result_predicate_from_compiled(refinement.predicate),
                proof_effect: match refinement.proof_effect {
                    CompiledPredicateProofEffect::Establishes => {
                        AuthoredPredicateProofEffect::Establishes
                    }
                    CompiledPredicateProofEffect::DoesNotEstablish => {
                        AuthoredPredicateProofEffect::DoesNotEstablish
                    }
                },
            })
            .collect(),
        conditional_indirect_writes: summary
            .conditional_indirect_writes
            .iter()
            .map(|write| AuthoredConditionalIndirectWrite {
                result_ordinal: write.result_ordinal,
                outcome: write.outcome,
                parameter_ordinal: write.parameter_ordinal,
                target: match write.target {
                    CompiledIndirectWriteTarget::Pointee => AuthoredIndirectWriteTarget::Pointee,
                },
            })
            .collect(),
        normal_return_refinements: summary
            .normal_return_refinements
            .iter()
            .map(|refinement| AuthoredNormalReturnRefinement {
                parameter_ordinal: refinement.parameter_ordinal,
                predicate: authored_result_predicate_from_compiled(refinement.predicate),
            })
            .collect(),
        normal_return_type_refinements: summary
            .normal_return_type_refinements
            .iter()
            .map(|refinement| AuthoredNormalReturnTypeRefinement {
                parameter_ordinal: refinement.parameter_ordinal,
                class_parameter_ordinal: refinement.class_parameter_ordinal,
                required_receiver_members: refinement.required_receiver_members.clone(),
            })
            .collect(),
        class_decorator_identity: summary.class_decorator_identity.as_ref().map(|identity| {
            AuthoredClassDecoratorIdentity {
                direct: identity.direct,
                factory_keywords: identity.factory_keywords.as_ref().map(|keywords| {
                    keywords
                        .iter()
                        .map(|keyword| AuthoredClassDecoratorKeyword {
                            name: keyword.name.clone(),
                            allowed_values: keyword.allowed_values.clone(),
                        })
                        .collect()
                }),
            }
        }),
    }
}

/// Prove the whole-manifest inventory invariants: no payload record id is
/// defined twice across shards, and every referenced id is defined.
///
/// The cost is proportional to every id in the manifest, so a reader that
/// decodes several shards of one manifest validates it once, not per shard
/// (#3101).
pub fn validate_manifest_inventory(manifest: &CompiledPackManifest) -> Result<(), ArtifactError> {
    let mut definitions = HashSet::new();
    let mut record_ids = HashSet::new();
    for descriptor in &manifest.shards {
        for id in &descriptor.defined_ids {
            if !definitions.insert(id) {
                return Err(ArtifactError::InvalidDescriptor(format!(
                    "payload record id `{id}` is defined more than once"
                )));
            }
            let record_id =
                if let Some(procedure_id) = id.strip_prefix(PROCEDURE_ID_INVENTORY_PREFIX) {
                    Some(procedure_id)
                } else if id.starts_with(PROCEDURE_TARGET_INVENTORY_PREFIX) {
                    None
                } else {
                    Some(id.as_str())
                };
            if let Some(record_id) = record_id
                && !record_ids.insert(record_id)
            {
                return Err(ArtifactError::InvalidDescriptor(format!(
                    "payload record id `{record_id}` is defined more than once"
                )));
            }
        }
    }
    for descriptor in &manifest.shards {
        for id in &descriptor.referenced_ids {
            if !definitions.contains(id) {
                return Err(ArtifactError::InvalidDescriptor(format!(
                    "payload record id `{id}` is referenced but not defined"
                )));
            }
        }
    }
    Ok(())
}

fn validate_text(
    value: &str,
    limits: &DecodeLimits,
    field: &'static str,
) -> Result<(), ArtifactError> {
    if value.is_empty() || value.len() > limits.max_text_bytes || value.contains('\0') {
        return Err(ArtifactError::InvalidDescriptor(format!(
            "{field} is empty, too long, or contains NUL"
        )));
    }
    Ok(())
}

/// Decoding accepts every supported schema version, not only the one this
/// build mints: an installed artifact keeps loading across a version bump and
/// is regenerated on its producer's normal cadence.
fn require_version(version: u32) -> Result<(), ArtifactError> {
    if SEMANTIC_MODEL_SUPPORTED_SCHEMA_VERSIONS.contains(&version) {
        Ok(())
    } else {
        Err(ArtifactError::UnsupportedVersion(version))
    }
}

fn digest_hex(domain: &[u8], bytes: &[u8]) -> String {
    lower_hex_string(&hash_domain_bytes(domain, bytes))
}
